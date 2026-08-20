#include <linux/init.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/statfs.h>
#include <linux/fs_struct.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/mountzero.h>

static struct kmem_cache *mz_rule_cachep, *mz_dir_cachep, *mz_uid_cachep;
atomic_t mz_active_rules = ATOMIC_INIT(0);
atomic_t mz_active_dirs = ATOMIC_INIT(0);
atomic_t mz_active_uids = ATOMIC_INIT(0);
DEFINE_STATIC_KEY_FALSE(mountzero_active_rules);
DEFINE_STATIC_KEY_FALSE(mountzero_active_dirs);
DEFINE_STATIC_KEY_FALSE(mountzero_active_uids);

/* logs */
#define mz_debug(fmt, ...) printk(KERN_DEBUG "MountZero: [DEBUG] " fmt, ##__VA_ARGS__)
#define mz_info(fmt, ...) printk(KERN_INFO "MountZero: " fmt, ##__VA_ARGS__)
#define mz_warn(fmt, ...) printk(KERN_WARNING "MountZero: [WARN] " fmt, ##__VA_ARGS__)
#define mz_err(fmt, ...)  printk(KERN_ERR "MountZero: [ERROR] " fmt, ##__VA_ARGS__)

/*** Verification & Compatibility Checks ***/

/**
 * mountzero_is_uid_blocked - Check if a specific UID is excluded from redirection
 * @uid: The User ID to check
 *
 * Returns true if the UID exists in the exclusion hash table.
 */
static inline bool mountzero_is_uid_blocked(uid_t uid) {
    struct mountzero_uid_node *entry;
    rcu_read_lock();
    hash_for_each_possible_rcu(mountzero_uid_ht, entry, node, uid) {
        if (entry->uid == uid) {
            rcu_read_unlock();
            return true;
        }
    }
    rcu_read_unlock();
    return false;
}

/**
 * __mountzero_should_skip - Determine if the current context should bypass hooks
 *
 * Returns true if MountZero is disabled, if running in interrupt context,
 * if recursion is detected, or if the current UID is in the blocklist.
 */
static __always_inline bool __mountzero_should_skip(void) {
    if (!static_branch_unlikely(&mountzero_active_rules)) return true;
    if (unlikely(!in_task() || in_nmi() || oops_in_progress)) return true;
    if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING))) return true;
    if (unlikely(static_branch_unlikely(&mountzero_active_uids))) {
        if (unlikely(mountzero_is_uid_blocked(current_uid().val))) return true;
    }
    return false;
}

/*** Helpers & Path Resolution ***/

/**
 * __mountzero_is_injected_file_rcu - Check if an inode number belongs to an injected file.
 * @inode: The inode to check
 *
 * This function performs a lockless check against the registered rules to determine
 * if the given inode corresponds to an injected file.
 * It checks both real and virtual inode hash tables.
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the result is being used.
 */
static inline bool __mountzero_is_injected_file_rcu(struct inode *inode) {
    struct mz_inode_node *node;
    hash_for_each_possible_rcu(mountzero_inodes_ht, node, node, inode->i_ino) {
        if (node->ino == inode->i_ino && node->dev == inode->i_sb->s_dev) {
            if (node->type & (MZ_INO_TYPE_REAL | MZ_INO_TYPE_VIRTUAL))
                return true;
        }
    }
    return false;
}

/**
 * __mountzero_is_traversal_allowed_rcu - Check if an inode number corresponds to a 
 * directory with traversal permissions
 * @inode: The inode to check
 *
 * This function checks if the given inode corresponds to a directory that allows traversal.
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the result is being used.
 */
static inline bool __mountzero_is_traversal_allowed_rcu(struct inode *inode) {
    struct mz_inode_node *node;
    hash_for_each_possible_rcu(mountzero_inodes_ht, node, node, inode->i_ino) {
        if (node->ino == inode->i_ino && node->dev == inode->i_sb->s_dev) {
            if (likely(node->type & MZ_INO_TYPE_DIR)) return true;
            break;
        }
    }
    return false;
}

/**
 * mountzero_build_path_from_pwd - Construct an absolute path using the current working directory
 * @rel_name: The relative filename to append to the current working directory
 * @name_len: The length of the relative filename
 * @out_len: Pointer to receive the length of the constructed path
 * @out_path: Pointer to receive the allocated path string
 * @fast_buf: Pointer to a pre-allocated stack buffer for fast path resolution
 *
 * This helper is used to reconstruct an absolute path for operations that provide
 * a relative filename, ensuring that MountZero can still resolve the intended target.
 *
 * This helper uses a fast stack buffer for common path sizes.
 * If the path exceeds the fast buffer, it allocates a full page from names_cache.
 * Returns a pointer to the buffer holding the path (fast_buf or a new page).
 * If a new page is returned, it must be freed with __putname().
 */
static const char *mountzero_build_path_from_pwd(const char *rel_name, size_t name_len, size_t *out_len,
                                                const char **out_path, char *fast_buf)
{
    struct path pwd;
    char *end_ptr, *cwd_str, *page_buf = fast_buf;
    size_t dir_len;

    rcu_read_lock();
    pwd = current->fs->pwd;
    path_get(&pwd);
    rcu_read_unlock();
    cwd_str = d_path(&pwd, page_buf, 512);

    if (IS_ERR(cwd_str)) {
        if (PTR_ERR(cwd_str) == -ENAMETOOLONG) {
            page_buf = __getname();
            if (unlikely(!page_buf)) { path_put(&pwd); return NULL; }
            cwd_str = d_path(&pwd, page_buf, PATH_MAX);
            if (IS_ERR(cwd_str)) { __putname(page_buf); path_put(&pwd); return NULL; }
        } else {
            path_put(&pwd);
            return NULL;
        }
    }
    path_put(&pwd);

    dir_len = strlen(cwd_str);
    if (likely(dir_len + name_len + 2 <= (page_buf != fast_buf ? PATH_MAX : 512))) {
        if (cwd_str != page_buf) {
            memmove(page_buf, cwd_str, dir_len);
            cwd_str = page_buf;
        }
        end_ptr = cwd_str + dir_len;
        if (dir_len > 0 && *(end_ptr - 1) != '/') { *end_ptr = '/'; end_ptr++; dir_len++; }
        memcpy(end_ptr, rel_name, name_len + 1);
        if (out_len) *out_len = dir_len + name_len;
        *out_path = cwd_str;
        return page_buf;
    }

    if (page_buf != fast_buf) __putname(page_buf);
    return NULL;
}

/**
 * mountzero_get_rule_by_inode - Look up the registered rule for an inode
 * @inode: The inode to query
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the returned rule is being used.
 */
static inline struct mountzero_rule *mountzero_get_rule_by_inode(struct inode *inode) {
    struct mz_inode_node *inode_node;
    hash_for_each_possible_rcu(mountzero_inodes_ht, inode_node, node, inode->i_ino) {
        if (inode_node->ino == inode->i_ino && inode_node->dev == inode->i_sb->s_dev) {
            switch (inode_node->type) {
                case MZ_INO_TYPE_REAL:
                    return container_of(inode_node, struct mountzero_rule, real_node);
                case MZ_INO_TYPE_VIRTUAL:
                    return container_of(inode_node, struct mountzero_rule, virt_node);
            }
        }
    }
    return NULL;
}

/**
 * mountzero_get_rule_by_path - Look up the rule for a virtual path
 * @pathname: The requested virtual path
 * @len: The length of the requested path
 *
 * Performs a fast hash lookup to find redirection rules.
 * Returns a pointer to the rule, or NULL if no rule matches.
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the returned rule is being used.
 */
static inline struct mountzero_rule *mountzero_get_rule_by_path(const char *pathname, size_t len) {
    struct mountzero_rule *rule;
    u32 hash = full_name_hash(NULL, pathname, len);
    hash_for_each_possible_rcu(mountzero_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->virt_node.len == len &&
             memcmp(pathname, rule->virtual_path, len) == 0) {
            return rule;
        }
    }
    return NULL;
}

/*** VFS Hooks & Injection Logic ***/

/**
 * mountzero_handle_dpath - Intercept d_path calls to hide real locations
 * @path: The path struct being resolved
 * @buf: The buffer to write the result into
 * @buflen: Length of the buffer
 *
 * Replaces the real physical path of an injected file with its intended 
 * virtual path to prevent information leaks in Userspace.
 * 
 * Returns a pointer within the buffer where the virtual path begins.
 */
char *mountzero_handle_dpath(const struct path *path, char *buf, int buflen) 
{
    struct mountzero_rule *rule;
    char *res; int len;

    if (unlikely(IS_ERR_OR_NULL(path) || !path->dentry || !path->dentry->d_inode)) return NULL;
    if (__mountzero_should_skip()) return NULL;

    rcu_read_lock();
    rule = mountzero_get_rule_by_inode(path->dentry->d_inode);

    if (likely(rule)) {
        len = rule->virt_node.len;
        if (likely(buflen >= len + 1)) {
            res = buf + buflen - len - 1;
            memcpy(res, rule->virtual_path, len + 1);
            mz_debug("d_path spoofed %s to %s\n", rule->real_path, rule->virtual_path);
            rcu_read_unlock();
            return res;
        }
    }

    rcu_read_unlock();
    return NULL;
}

/**
 * mountzero_handle_permission - Enforce permissions for injected structure
 * @inode: The inode being accessed
 * @mask: The requested permission mask
 *
 * Return: > 0 to bypass native checks (allow read/exec), 
 *         < 0 to explicitly deny (block writes), 
 *           0 to fallback to standard VFS permissions.
 */
int mountzero_handle_permission(struct inode *inode, int mask)
{
    bool is_injected = false, is_dir = false;

    if (__mountzero_should_skip() || IS_ERR_OR_NULL(inode)) return 0;

    rcu_read_lock();
    is_injected = __mountzero_is_injected_file_rcu(inode);
    if (!is_injected && likely(S_ISDIR(inode->i_mode))) {
        is_dir = __mountzero_is_traversal_allowed_rcu(inode);
    }
    rcu_read_unlock();

    if (is_dir && !is_injected) {
        if (mask & (MAY_READ | MAY_WRITE | MAY_APPEND)) return 0;
        if (mask & MAY_EXEC) return 1;
    }

    if (is_injected) {
        if (mask & (MAY_WRITE | MAY_APPEND)) return 0;
        return 1; 
    }

    return 0;
}

/**
 * mountzero_handle_getname - Redirect paths during filename struct creation
 * @name: The original filename struct requested by userspace
 *
 * This is the primary entry point for path redirection. If the requested 
 * path matches a rule, it alters the filename struct to point to the real 
 * physical location on disk.
 * 
 * Returns the modified filename struct, or the original if no match.
 */
struct filename *mountzero_handle_getname(struct filename *name)
{
    struct mountzero_rule *rule;
    const char *check_name, *s, *last_slash, *page_buf = NULL;
    size_t name_len, b_len, r_len;
    bool basename_match = false;
    u32 b_hash;
    char fast_buf[512];

    if (unlikely(__mountzero_should_skip()))
        return name;

    if (unlikely(IS_ERR_OR_NULL(name) || !name->name))
        return name;

    s = name->name;
    name_len = strlen(s);
    if (unlikely(name_len == 1 && s[0] == '/'))
        return name;

    last_slash = strrchr(s, '/');
    check_name = (last_slash && *(last_slash + 1) != '\0') ? last_slash + 1 : s;
    b_len = name_len - (check_name - s);
    b_hash = full_name_hash(NULL, check_name, b_len);

    rcu_read_lock();
    if (unlikely(s[0] == '/' && !list_empty(&mountzero_private_dirs_list) && current_uid().val >= AID_APP_START)) {
        struct mountzero_dir_node *priv_dir;
        list_for_each_entry_rcu(priv_dir, &mountzero_private_dirs_list, private_list) {
            size_t len = priv_dir->dir.len;
            if (name_len >= len && s[1] == priv_dir->dir_path[1] && memcmp(s, priv_dir->dir_path, len) == 0) {
                if (unlikely(s[len] == '\0' || s[len] == '/')) {
                    goto out_unlock;
                }
            }
        }
    }

    hash_for_each_possible_rcu(mountzero_basenames_ht, rule, basename_node, b_hash) {
        if (rule->b_len == b_len && memcmp(rule->basename, check_name, b_len) == 0) {
            basename_match = true;
            break;
        }
    }
    rcu_read_unlock();
    if (unlikely(!basename_match)) return name;

    check_name = s;
    r_len = name_len;
    if (unlikely(s[0] != '/')) {
        page_buf = mountzero_build_path_from_pwd(s, name_len, &r_len, &check_name, fast_buf);
        if (!page_buf) return name;
    }

    rcu_read_lock();
    rule = mountzero_get_rule_by_path(check_name, r_len);
    if (likely(rule)) {
        mz_debug("Redirected: %s -> %s\n", check_name, rule->real_path);
        memcpy((char *)name->name, rule->real_path, rule->real_node.len);
        ((char *)name->name)[rule->real_node.len] = '\0';
    }
    rcu_read_unlock();
    if (page_buf && page_buf != fast_buf) __putname(page_buf);
    return name;

out_unlock:
    rcu_read_unlock();
    putname(name);
    return ERR_PTR(-ENOENT);
}

/**
 * mountzero_handle_iterate_dir - Replaces the native VFS iterate function
 * @file: The directory file being iterated
 * @ctx: The VFS directory context
 *
 * This function wraps around the native iterate mechanisms to seamlessly
 * inject virtual directory entries into the directory listing.
 */
int mountzero_handle_iterate_dir(struct file *file, struct dir_context *ctx)
{
    struct mountzero_dir_node *curr_dir;
    struct mz_child_array *array = NULL;
    loff_t old_pos = ctx->pos;
    loff_t mountzero_magic_pos = 0x7000000000000000ULL;
    unsigned long v_index;
    int res = 0;
    u32 i;

    if (!static_branch_unlikely(&mountzero_active_dirs) || __mountzero_should_skip()) {
        if (file->f_op->iterate_shared)
            return file->f_op->iterate_shared(file, ctx);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        else if (file->f_op->iterate)
            return file->f_op->iterate(file, ctx);
#endif
        return -ENOTDIR;
    }

#ifdef CONFIG_COMPAT
    if (in_compat_syscall()) mountzero_magic_pos = 0x7E000000;
#endif
    if (ctx->pos < mountzero_magic_pos) {
        if (file->f_op->iterate_shared)
            res = file->f_op->iterate_shared(file, ctx);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        else if (file->f_op->iterate)
            return file->f_op->iterate(file, ctx);
#endif
        else
            return -ENOTDIR;
    }

    if (res >= 0 && (ctx->pos == old_pos || ctx->pos >= mountzero_magic_pos)) {
        struct mz_inode_node *inode_node;
        struct inode *dir_inode = file_inode(file);
        if (!dir_inode) return res;

        rcu_read_lock();
        hash_for_each_possible_rcu(mountzero_inodes_ht, inode_node, node, dir_inode->i_ino) {
            if (likely(inode_node->ino == dir_inode->i_ino && inode_node->dev == dir_inode->i_sb->s_dev)) {
                if (likely(inode_node->type & MZ_INO_TYPE_DIR)) {
                    curr_dir = container_of(inode_node, struct mountzero_dir_node, dir);
                    array = rcu_dereference(curr_dir->child_array);
                    if (likely(array && atomic_inc_not_zero(&array->refcnt))) break;
                    array = NULL;
                }
                break; 
            }
        }
        rcu_read_unlock();
        if (!array) return res;

        if (ctx->pos >= mountzero_magic_pos && ctx->pos < mountzero_magic_pos + 100000) {
            v_index = (unsigned long)(ctx->pos - mountzero_magic_pos);
        } else {
            v_index = 0;
            ctx->pos = mountzero_magic_pos;
        }

        for (i = v_index; i < array->num_children; i++) {
            struct mountzero_child_name *child = &array->entries[i];
            if (!dir_emit(ctx, child->name, child->name_len, child->fake_ino, child->d_type))
                break;
            ctx->pos = mountzero_magic_pos + i + 1;
        }

        if (atomic_dec_and_test(&array->refcnt)) kfree_rcu(array, rcu);
    }

    return res;
}

/*** Metadata Spoofing ***/

/**
 * mountzero_handle_getattr - Wrapper for vfs_getattr intercept
 * @ret: The return code from the native vfs_getattr execution
 * @path: The path being evaluated
 * @stat: The stat struct populated by the kernel
 *
 * Applies the stat spoofing logic only if the original lookup succeeded.
 * Returns the original return code.
 */
int mountzero_handle_getattr(int ret, const struct path *path, struct kstat *stat)
{
    struct mz_inode_node *inode_node;
    struct mountzero_rule *rule;
    struct inode *inode;

    if (unlikely(ret != 0 || __mountzero_should_skip())) return ret;
    if (unlikely(IS_ERR_OR_NULL(path) || IS_ERR_OR_NULL(stat) || IS_ERR_OR_NULL(path->dentry))) return ret;

    inode = d_backing_inode(path->dentry);
    if (unlikely(IS_ERR_OR_NULL(inode) || IS_ERR_OR_NULL(inode->i_sb))) return ret;

    rcu_read_lock();
    hash_for_each_possible_rcu(mountzero_inodes_ht, inode_node, node, inode->i_ino) {
        if (inode_node->ino == inode->i_ino && inode_node->dev == inode->i_sb->s_dev) {
            if (inode_node->type & MZ_INO_TYPE_REAL) {
                rule = container_of(inode_node, struct mountzero_rule, real_node);
                stat->ino = READ_ONCE(rule->virt_node.ino);
                if (rule->virt_node.dev != 0)
                    stat->dev = READ_ONCE(rule->virt_node.dev);
            }
            break;
        }
    }
    rcu_read_unlock();

    return ret;
}

/**
 * mountzero_spoof_statfs - Forge filesystem type data
 * @path: The path being evaluated
 * @buf: The statfs struct to modify
 *
 * Injects the correct Magic Number (e.g., ext4, erofs) to match the 
 * virtual partition, preventing detection via filesystem type checks.
 */
void mountzero_spoof_statfs(const struct path *path, struct kstatfs *buf)
{
    struct mz_inode_node *inode_node;
    struct mountzero_rule *rule = NULL;
    struct inode *inode;

    if (unlikely(__mountzero_should_skip() || IS_ERR_OR_NULL(path) || IS_ERR_OR_NULL(buf) || IS_ERR_OR_NULL(path->dentry))) return;

    inode = d_backing_inode(path->dentry);
    if (unlikely(IS_ERR_OR_NULL(inode) || IS_ERR_OR_NULL(inode->i_sb))) return;

    rcu_read_lock();
    hash_for_each_possible_rcu(mountzero_inodes_ht, inode_node, node, inode->i_ino) {
        if (inode_node->ino == inode->i_ino && inode_node->dev == inode->i_sb->s_dev) {
            switch (inode_node->type) {
                case MZ_INO_TYPE_REAL:
                    rule = container_of(inode_node, struct mountzero_rule, real_node);
                    break;
                case MZ_INO_TYPE_VIRTUAL:
                    rule = container_of(inode_node, struct mountzero_rule, virt_node);
                    break;
                default:
                    goto unlock; 
            }
            if (rule && rule->v_fs_type != 0) 
                buf->f_type = READ_ONCE(rule->v_fs_type);
            break;
        }
    }

unlock:
    rcu_read_unlock();
}

/**
 * mountzero_spoof_mmap_metadata - Forge VMA metadata for /proc/self/maps
 * @inode: The underlying inode of the mapped memory
 * @dev: Pointer to the device ID variable to overwrite
 * @ino: Pointer to the inode number variable to overwrite
 *
 * Ensures that shared libraries or binaries executed via MountZero show 
 * the correct virtual device and inode in process memory maps.
 * 
 * Returns true if the metadata was spoofed.
 */
bool mountzero_spoof_mmap_metadata(struct inode *inode, dev_t *dev, unsigned long *ino)
{
    struct mz_inode_node *inode_node;
    struct mountzero_rule *rule;

    if (unlikely(__mountzero_should_skip() || IS_ERR_OR_NULL(inode) ||
                 IS_ERR_OR_NULL(inode->i_sb) || IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(ino))) 
        return false;

    rcu_read_lock();
    hash_for_each_possible_rcu(mountzero_inodes_ht, inode_node, node, inode->i_ino) {
        if (inode_node->ino == inode->i_ino && inode_node->dev == inode->i_sb->s_dev) {
            if (inode_node->type & MZ_INO_TYPE_REAL) {
                rule = container_of(inode_node, struct mountzero_rule, real_node);
                *dev = READ_ONCE(rule->virt_node.dev);
                *ino = READ_ONCE(rule->virt_node.ino);
                rcu_read_unlock();
                return true;
            }
            break;
        }
    }
    rcu_read_unlock();
    return false;
}

/*** Module Management ***/

/**
 * __mountzero_get_or_create_dir - Factory function to retrieve or create a directory node
 * @ino: Inode number of the directory
 * @dev: Device ID of the directory
 *
 * Checks if a directory node already exists for the given inode. If not, allocates
 * a new node from mz_dir_cachep, initializes its lists, and adds it to the global
 * hash table.
 *
 * Return a pointer to the mountzero_dir_node on success, NULL on failure (ENOMEM).
 */
static inline struct mountzero_dir_node* __mountzero_get_or_create_dir(unsigned long ino, dev_t dev)
{
    struct mz_inode_node *inode_node;
    struct mountzero_dir_node *dir_node;

    hash_for_each_possible(mountzero_inodes_ht, inode_node, node, ino) {
        if (inode_node->ino == ino && inode_node->dev == dev) {
            if (likely(inode_node->type & MZ_INO_TYPE_DIR)) {
                return container_of(inode_node, struct mountzero_dir_node, dir);
            }
        }
    }

    dir_node = kmem_cache_alloc(mz_dir_cachep, GFP_KERNEL);
    if (unlikely(!dir_node)) return NULL;

    dir_node->dir.ino = ino;
    dir_node->dir.dev = dev;
    dir_node->dir.len = 0;
    dir_node->dir.type = MZ_INO_TYPE_DIR;
    dir_node->dir_path = NULL;
    dir_node->is_private = false;
    INIT_LIST_HEAD(&dir_node->private_list);
    RCU_INIT_POINTER(dir_node->child_array, NULL);
    hash_add_rcu(mountzero_inodes_ht, &dir_node->dir.node, ino);
    atomic_inc(&mz_active_dirs);
    if (atomic_read(&mz_active_dirs) == 1) static_branch_enable(&mountzero_active_dirs);

    return dir_node;
}

/* __mountzero_collect_parents - Walks the dentry tree to register directory hierarchy
 * @rule: The rule containing the absolute real_path string
 * @d: A valid referenced dentry resolved from kern_path
 *
 * This function recursively climbs the dentry tree starting from the provided 
 * dentry. It registers every parent inode encountered and handles the extraction 
 * of private directory paths automatically when traversal permissions are restricted.
 *
 * This function relies on the caller to provide a valid reference (dget).
 */
static void __mountzero_collect_parents(struct mountzero_rule *rule, struct dentry *d)
{
    struct dentry *parent;
    char *r_tmp = rule->real_path, *slash, *slashes[32];
    int p_count = 0;

    while (d && !IS_ROOT(d) && p_count < 32) {
        struct inode *inode = d_backing_inode(d);
        if (likely(inode && S_ISDIR(inode->i_mode))) {
            struct mountzero_dir_node *dir_node = __mountzero_get_or_create_dir(inode->i_ino, inode->i_sb->s_dev);
            if (likely(dir_node)) {
                rule->parent_dir = dir_node;
                if (unlikely(!(inode->i_mode & S_IXOTH) && !dir_node->dir_path)) {
                    dir_node->is_private = true;
                    mz_debug("Registered private dir: %s (ino: %lu)\n", r_tmp, inode->i_ino);
                    dir_node->dir.len = strlen(r_tmp);
                    dir_node->dir_path = kmemdup_nul(r_tmp, dir_node->dir.len, GFP_KERNEL);
                    if (likely(dir_node->dir_path)) {
                        list_add_tail_rcu(&dir_node->private_list, &mountzero_private_dirs_list);
                    }
                }
            }
        }

        slash = strrchr(r_tmp, '/');
        if (!slash || slash == r_tmp) break;
        *slash = '\0';
        slashes[p_count++] = slash;

        parent = dget_parent(d);
        dput(d);
        d = parent;
    }

    if (d) dput(d);
    while (p_count > 0) *slashes[--p_count] = '/';
}

/**
 * __mountzero_inject_child_locked - Atomically inserts a virtual child into a parent
 * @dir_node: The parent directory node to inject into
 * @rule: The rule associated with the child being injected (used for metadata inheritance)
 * @name: Filename of the child
 * @name_len: Length of the name string
 * @name_hash: Precalculated hash of the name string
 * @type: File type (DT_DIR, DT_REG, etc.)
 * @child_fake_ino: The synthetic inode number for the virtual file
 *
 * This function performs an hash check to see if the child already exists 
 * to prevent duplicates, then appends it to the directory's child array.
 *
 * NOTE: Caller MUST hold the mutex lock to prevent concurrent writers, 
 * but RCU readers can continue without blocking.
 */
static void __mountzero_inject_child_locked(struct mountzero_dir_node *dir_node, struct mountzero_rule *rule,
                                          const char *name, size_t name_len, u32 name_hash,
                                          unsigned char type, unsigned long child_fake_ino)
{
    struct mz_child_array *old_array, *new_array;
    u32 i, old_num = 0;

    if (unlikely(!dir_node)) return;
    rule->parent_dir = dir_node;

    old_array = rcu_dereference_protected(dir_node->child_array, lockdep_is_held(&mountzero_write_mutex));
    if (old_array) {
        old_num = old_array->num_children;
        for (i = 0; i < old_num; i++) {
            if (old_array->entries[i].name_len == name_len &&
                !memcmp(old_array->entries[i].name, name, name_len)) {
                return;
            }
        }
    }

    new_array = kmalloc(sizeof(struct mz_child_array) + (old_num + 1) * sizeof(struct mountzero_child_name), GFP_KERNEL);
    if (unlikely(!new_array)) return;

    atomic_set(&new_array->refcnt, 1);
    new_array->num_children = old_num + 1;

    if (old_array) memcpy(new_array->entries, old_array->entries, 
                          old_num * sizeof(struct mountzero_child_name));

    memcpy(new_array->entries[old_num].name, name, name_len + 1);
    new_array->entries[old_num].name_len = (u16)name_len;
    new_array->entries[old_num].d_type = type;
    new_array->entries[old_num].fake_ino = child_fake_ino;
    rcu_assign_pointer(dir_node->child_array, new_array);

    if (old_array && atomic_dec_and_test(&old_array->refcnt)) {
        kfree_rcu(old_array, rcu);
    }
}

static void __mountzero_delete_child_locked(struct mountzero_dir_node *dir_node, unsigned long fake_ino, 
                                          struct hlist_head *d_victims)
{
    struct mz_child_array *old_array, *new_array;
    int found_idx = -1;
    u32 i, num, dst = 0;

    old_array = rcu_dereference_protected(dir_node->child_array, lockdep_is_held(&mountzero_write_mutex));
    if (!old_array) return;

    num = old_array->num_children;
    for (i = 0; i < num; i++) {
        if (old_array->entries[i].fake_ino == fake_ino) {
            found_idx = i;
            break;
        }
    }
    if (found_idx == -1) return;

    if (num == 1) {
        rcu_assign_pointer(dir_node->child_array, NULL);
        if (atomic_dec_and_test(&old_array->refcnt)) kfree_rcu(old_array, rcu);
        hash_del_rcu(&dir_node->dir.node);
        if (unlikely(dir_node->is_private)) list_del_rcu(&dir_node->private_list);
        atomic_dec(&mz_active_dirs);
        if (atomic_read(&mz_active_dirs) == 0) static_branch_disable(&mountzero_active_dirs);
        hlist_add_head(&dir_node->dir.node, d_victims);
    } else {
        new_array = kmalloc(sizeof(struct mz_child_array) + (num - 1) * sizeof(struct mountzero_child_name), GFP_KERNEL);
        if (unlikely(!new_array)) return;

        atomic_set(&new_array->refcnt, 1);
        new_array->num_children = num - 1;
        for (i = 0; i < num; i++) {
            if (i == found_idx) continue;
            memcpy(&new_array->entries[dst++], &old_array->entries[i], sizeof(struct mountzero_child_name));
        }
        rcu_assign_pointer(dir_node->child_array, new_array);
        if (atomic_dec_and_test(&old_array->refcnt))
            kfree_rcu(old_array, rcu);
    }
}

/**
 * mountzero_generate_virtual_topology - Autogenerates intermediate directory rules
 * @rule: The main rule being added
 *
 * Walks the path backwards using in-place mutation to find the closest
 * native parent, inherits its metadata (s_dev, s_magic), and auto-injects
 * intermediate virtual directory rules to satisfy VFS lookups.
 *
 * Returns 0 on success, or negative error code (e.g., -ENOMEM) on failure.
 */
static int mountzero_generate_virtual_topology(struct mountzero_rule *rule)
{
    struct mountzero_rule *ex, *irule = NULL, *t_rule, *pending_rules[32];
    struct path p_path, r_path_struct;
    char *v_tmp = rule->virtual_path, *r_tmp = rule->real_path;
    char *slash_v, *slash_r, *b_slash, *slashes_v[32], *slashes_r[32];
    int cur_v_len = rule->virt_node.len, cur_r_len = rule->real_node.len;
    int p_count = 0, err = 0, current_flags = rule->flags;
    unsigned long inherited_dev = 0, inherited_fs_type = 0;
    unsigned long current_parent_ino; dev_t current_parent_dev;
    const char *b_name_inter, *child_name;
    bool inter_exists;
    size_t child_name_len;
    u32 child_name_hash, h_inter;

    while (p_count < 32) {
        slash_v = strrchr(v_tmp, '/');
        slash_r = r_tmp ? strrchr(r_tmp, '/') : NULL; 
        if (slash_r == r_tmp) slash_r = NULL;
        if (!slash_v || slash_v == v_tmp) {
            if (likely(kern_path("/", LOOKUP_FOLLOW, &p_path) == 0)) {
                current_parent_ino = d_backing_inode(p_path.dentry)->i_ino;
                current_parent_dev = d_backing_inode(p_path.dentry)->i_sb->s_dev;
                child_name = v_tmp + 1;
                child_name_len = strlen(child_name);
                child_name_hash = full_name_hash(NULL, child_name, child_name_len);
                t_rule = (p_count == 0) ? rule : pending_rules[p_count - 1];
                __mountzero_inject_child_locked(__mountzero_get_or_create_dir(current_parent_ino, current_parent_dev),
                                              t_rule, child_name, child_name_len, child_name_hash,
                                              (current_flags & MZ_FLAG_IS_DIR) ? DT_DIR : DT_REG, t_rule->v_hash);
                path_put(&p_path);
            }
            break;
        }

        *slash_v = '\0';
        slashes_v[p_count] = slash_v;
        cur_v_len = slash_v - v_tmp;

        if (slash_r) {
            *slash_r = '\0';
            slashes_r[p_count] = slash_r;
            cur_r_len = slash_r - r_tmp;
        } else {
            slashes_r[p_count] = NULL;
        }

        pending_rules[p_count] = NULL; 
        p_count++;
        h_inter = full_name_hash(NULL, v_tmp, cur_v_len);
        inter_exists = false;

        hash_for_each_possible(mountzero_rules_ht, ex, vpath_node, h_inter) {
            if (ex->virt_node.len == cur_v_len && memcmp(ex->virtual_path, v_tmp, cur_v_len) == 0) {
                inherited_dev = ex->virt_node.dev;
                inherited_fs_type = ex->v_fs_type;
                current_parent_ino = ex->virt_node.ino;
                current_parent_dev = ex->virt_node.dev;
                inter_exists = true;
                break;
            }
        }

        if (inter_exists) {
            child_name = slash_v + 1;
            child_name_len = strlen(child_name);
            child_name_hash = full_name_hash(NULL, child_name, child_name_len);
            t_rule = (p_count == 1) ? rule : pending_rules[p_count - 2];
            __mountzero_inject_child_locked(__mountzero_get_or_create_dir(current_parent_ino, current_parent_dev),
                                          t_rule, child_name, child_name_len, child_name_hash,
                                          (current_flags & MZ_FLAG_IS_DIR) ? DT_DIR : DT_REG, t_rule->v_hash);
            break;
        }

        if (likely(kern_path(v_tmp, LOOKUP_FOLLOW, &p_path) == 0)) {
            inherited_dev = p_path.dentry->d_sb->s_dev;
            if (p_path.dentry->d_sb->s_op->statfs) {
                struct kstatfs st;
                p_path.dentry->d_sb->s_op->statfs(p_path.dentry, &st);
                inherited_fs_type = st.f_type;
            } else {
                inherited_fs_type = p_path.dentry->d_sb->s_magic;
            }
            current_parent_ino = d_backing_inode(p_path.dentry)->i_ino;
            current_parent_dev = d_backing_inode(p_path.dentry)->i_sb->s_dev;
            child_name = slash_v + 1;
            child_name_len = strlen(child_name);
            child_name_hash = full_name_hash(NULL, child_name, child_name_len);
            t_rule = (p_count == 1) ? rule : pending_rules[p_count - 2];
            __mountzero_inject_child_locked(__mountzero_get_or_create_dir(current_parent_ino, current_parent_dev),
                                          t_rule, child_name, child_name_len, child_name_hash,
                                          (current_flags & MZ_FLAG_IS_DIR) ? DT_DIR : DT_REG, t_rule->v_hash);
            path_put(&p_path);
            break; 
        } else {
            pending_rules[p_count - 1] = kmem_cache_alloc(mz_rule_cachep, GFP_KERNEL);
            if (unlikely(!pending_rules[p_count - 1])) {
                err = -ENOMEM;
                break;
            }

            irule = pending_rules[p_count - 1];

            INIT_LIST_HEAD(&irule->list);
            INIT_HLIST_NODE(&irule->vpath_node);
            INIT_HLIST_NODE(&irule->basename_node);

            irule->virtual_path = kmemdup_nul(v_tmp, cur_v_len, GFP_KERNEL);
            irule->real_path = slash_r ? kmemdup_nul(r_tmp, cur_r_len, GFP_KERNEL) : kstrdup("/", GFP_KERNEL);
            if (unlikely(!irule->virtual_path || !irule->real_path)) {
                if (irule->virtual_path) kfree(irule->virtual_path);
                if (irule->real_path) kfree(irule->real_path);
                kmem_cache_free(mz_rule_cachep, irule);
                pending_rules[p_count - 1] = NULL;
                err = -ENOMEM;
                break;
            }

            b_slash = strrchr(irule->virtual_path, '/');
            b_name_inter = b_slash ? b_slash + 1 : irule->virtual_path;
            irule->basename = b_name_inter;
            irule->b_len = (u16)strlen(b_name_inter);
            irule->v_hash = h_inter;
            irule->flags = MZ_FLAG_IS_DIR;

            irule->virt_node.dev = 0;
            irule->virt_node.ino = (unsigned long)h_inter;
            irule->virt_node.len = (u16)cur_v_len;
            irule->virt_node.type = MZ_INO_TYPE_VIRTUAL;
            irule->real_node.ino = 0;
            irule->real_node.dev = 0;
            irule->real_node.len = (u16)(slash_r ? cur_r_len : 1);
            irule->real_node.type = MZ_INO_TYPE_REAL;

            if (slash_r) {
                if (likely(kern_path(irule->real_path, LOOKUP_FOLLOW, &r_path_struct) == 0)) {
                    irule->real_node.ino = d_backing_inode(r_path_struct.dentry)->i_ino;
                    irule->real_node.dev = r_path_struct.dentry->d_sb->s_dev;
                    path_put(&r_path_struct);
                }
            }
        }
        current_flags = MZ_FLAG_IS_DIR;
    }

    while (p_count > 0) {
        p_count--;
        if (slashes_v[p_count]) *slashes_v[p_count] = '/';
        if (slashes_r[p_count]) *slashes_r[p_count] = '/';

        if (pending_rules[p_count]) {
            irule = pending_rules[p_count];

            if (likely(err == 0)) {
                u32 bh = full_name_hash(NULL, irule->basename, irule->b_len);
                irule->virt_node.dev = inherited_dev;
                irule->v_fs_type = inherited_fs_type;

                hash_add_rcu(mountzero_basenames_ht, &irule->basename_node, bh);
                hash_add_rcu(mountzero_rules_ht, &irule->vpath_node, irule->v_hash);
                if (irule->real_node.ino) hash_add_rcu(mountzero_inodes_ht, &irule->real_node.node, irule->real_node.ino);
                hash_add_rcu(mountzero_inodes_ht, &irule->virt_node.node, irule->virt_node.ino);
                
                list_add_tail_rcu(&irule->list, &mountzero_rules_list);
                atomic_inc(&mz_active_rules);
                if (atomic_read(&mz_active_rules) == 1) static_branch_enable(&mountzero_active_rules);
            } else {
                kfree(irule->virtual_path);
                kfree(irule->real_path);
                kmem_cache_free(mz_rule_cachep, irule);
            }
        }
    }

    if (likely(err == 0)) {
        rule->virt_node.dev = inherited_dev;
        rule->v_fs_type = inherited_fs_type;
    }

    return err;
}

/*** Rule Operations ***/

static int __mountzero_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags)
{
    struct mountzero_rule *rule, *existing, *victim = NULL;
    struct path path_main, r_path_struct_main;
    struct dentry *r_path_dentry = NULL;
    char *slash;
    const char *b_name;
    u32 hash, b_hash;
    int err = 0;
    bool v_path_exists = false; 

    if (!v_path || !r_path) return -EINVAL;

    hash = full_name_hash(NULL, v_path, v_len);
    rule = kmem_cache_alloc(mz_rule_cachep, GFP_KERNEL);
    if (!rule)
        return -ENOMEM;

    rule->virtual_path = kmemdup_nul(v_path, v_len, GFP_KERNEL);
    rule->real_path = kmemdup_nul(r_path, r_len, GFP_KERNEL);

    if (!rule->virtual_path || !rule->real_path) {
        if (rule->virtual_path) kfree(rule->virtual_path);
        if (rule->real_path) kfree(rule->real_path);
        kmem_cache_free(mz_rule_cachep, rule);
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&rule->list);
    INIT_HLIST_NODE(&rule->vpath_node);
    INIT_HLIST_NODE(&rule->basename_node);

    slash = strrchr(rule->virtual_path, '/');
    b_name = slash ? slash + 1 : rule->virtual_path;
    rule->basename = b_name;
    rule->b_len = strlen(b_name);
    rule->v_hash = hash;
    rule->flags = flags;

    rule->real_node.ino = 0;
    rule->real_node.dev = 0;
    rule->real_node.len = r_len;
    rule->real_node.type = MZ_INO_TYPE_REAL;
    rule->virt_node.ino = 0;
    rule->virt_node.dev = 0;
    rule->virt_node.len = v_len;
    rule->virt_node.type = MZ_INO_TYPE_VIRTUAL;

    if (kern_path(rule->real_path, LOOKUP_FOLLOW, &r_path_struct_main) == 0) {
        struct inode *r_inode = d_backing_inode(r_path_struct_main.dentry);
        rule->real_node.ino = r_inode->i_ino;
        rule->real_node.dev = r_path_struct_main.dentry->d_sb->s_dev;
        if (S_ISDIR(r_inode->i_mode)) rule->flags |= MZ_FLAG_IS_DIR;
        r_path_dentry = dget(r_path_struct_main.dentry);
        path_put(&r_path_struct_main);
    }

    if (kern_path(rule->virtual_path, LOOKUP_FOLLOW, &path_main) == 0) {
        rule->virt_node.ino = d_backing_inode(path_main.dentry)->i_ino;
        rule->virt_node.dev = path_main.dentry->d_sb->s_dev;
        if (path_main.dentry->d_sb->s_op->statfs) {
            struct kstatfs st;
            path_main.dentry->d_sb->s_op->statfs(path_main.dentry, &st);
            rule->v_fs_type = st.f_type;
        } else {
            rule->v_fs_type = path_main.dentry->d_sb->s_magic;
        }
        path_put(&path_main);
        v_path_exists = true;
        mz_debug("Resolved physical backing for %s (ino: %lu)\n", rule->virtual_path, rule->virt_node.ino);
    } else {
        rule->virt_node.ino = (unsigned long)hash;
    }

    mutex_lock(&mountzero_write_mutex);
    hash_for_each_possible(mountzero_rules_ht, existing, vpath_node, hash) {
        if (existing->v_hash == hash && existing->virt_node.len == v_len &&
             memcmp(existing->virtual_path, rule->virtual_path, v_len) == 0) {
            hash_del_rcu(&existing->vpath_node);
            hash_del_rcu(&existing->basename_node);
            if (existing->real_node.ino) hash_del_rcu(&existing->real_node.node);
            if (existing->virt_node.ino) hash_del_rcu(&existing->virt_node.node);
            list_del_rcu(&existing->list);
            atomic_dec(&mz_active_rules);
            victim = existing;
            mz_info("Shadowing existing rule for: %s\n", rule->virtual_path);
            break;
        }
    }

    if (!v_path_exists) {
        err = mountzero_generate_virtual_topology(rule);
        if (err != 0) {
            mutex_unlock(&mountzero_write_mutex);
            if (r_path_dentry) dput(r_path_dentry);
            kfree(rule->virtual_path);
            kfree(rule->real_path);
            kmem_cache_free(mz_rule_cachep, rule);
            return err;
        }
    }
    
    if (r_path_dentry)
        __mountzero_collect_parents(rule, r_path_dentry);

    b_hash = full_name_hash(NULL, rule->basename, rule->b_len);
    hash_add_rcu(mountzero_basenames_ht, &rule->basename_node, b_hash);
    hash_add_rcu(mountzero_rules_ht, &rule->vpath_node, hash);

    if (rule->real_node.ino)
        hash_add_rcu(mountzero_inodes_ht, &rule->real_node.node, rule->real_node.ino);

    if (rule->virt_node.ino)
        hash_add_rcu(mountzero_inodes_ht, &rule->virt_node.node, rule->virt_node.ino);

    list_add_tail_rcu(&rule->list, &mountzero_rules_list);
    atomic_inc(&mz_active_rules);
    if (atomic_read(&mz_active_rules) == 1) static_branch_enable(&mountzero_active_rules);
    mutex_unlock(&mountzero_write_mutex);

    if (unlikely(victim)) {
        synchronize_rcu();
        kfree(victim->virtual_path);
        kfree(victim->real_path);
        kmem_cache_free(mz_rule_cachep, victim);
    }

    mz_info("Successfully added rule: %s -> %s\n", rule->virtual_path, rule->real_path);
    return 0;
}

static void __mountzero_del_rule(const char *v_path, size_t v_len,
                               struct list_head *r_victims,
                               struct hlist_head *d_victims)
{
    struct mountzero_rule *rule;
    u32 hash = full_name_hash(NULL, v_path, v_len);

    hash_for_each_possible(mountzero_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->virt_node.len == v_len &&
            memcmp(rule->virtual_path, v_path, v_len) == 0) {
            hash_del_rcu(&rule->vpath_node);
            hash_del_rcu(&rule->basename_node);
            if (rule->real_node.ino) hash_del_rcu(&rule->real_node.node);
            if (rule->virt_node.ino) hash_del_rcu(&rule->virt_node.node);
            list_del_rcu(&rule->list);
            atomic_dec(&mz_active_rules);
            if (atomic_read(&mz_active_rules) == 0) static_branch_disable(&mountzero_active_rules);
            list_add_tail(&rule->list, r_victims);
            if (rule->parent_dir)
                __mountzero_delete_child_locked(rule->parent_dir, hash, d_victims);
            break;
        }
    }
}

static void __mountzero_clear_all(void)
{
    struct mountzero_rule *rule, *tmp_rule;
    struct mountzero_dir_node *dir_node, *tmp_dir;
    struct mountzero_uid_node *uid_node;
    struct mz_inode_node *inode_node;
    struct hlist_node *hlist_tmp;
    struct mz_child_array *array;
    LIST_HEAD(rule_victims);
    LIST_HEAD(dir_victims);
    HLIST_HEAD(uid_victims);
    int bkt;

    list_for_each_entry_safe(rule, tmp_rule, &mountzero_rules_list, list) {
        hash_del_rcu(&rule->vpath_node);
        hash_del_rcu(&rule->basename_node);
        if (rule->real_node.ino) hash_del_rcu(&rule->real_node.node);
        if (rule->virt_node.ino) hash_del_rcu(&rule->virt_node.node);
        list_move_tail(&rule->list, &rule_victims);
    }

    hash_for_each_safe(mountzero_uid_ht, bkt, hlist_tmp, uid_node, node) {
        hash_del_rcu(&uid_node->node);
        hlist_add_head(&uid_node->node, &uid_victims);
    }

    hash_for_each_safe(mountzero_inodes_ht, bkt, hlist_tmp, inode_node, node) {
        if (inode_node->type & MZ_INO_TYPE_DIR) {
            dir_node = container_of(inode_node, struct mountzero_dir_node, dir);
            hash_del_rcu(&inode_node->node);
            array = rcu_dereference_protected(dir_node->child_array, 1);
            if (array) kfree_rcu(array, rcu);
            if (dir_node->is_private) list_del_rcu(&dir_node->private_list);
            list_add_tail(&dir_node->private_list, &dir_victims);
        }
    }

    atomic_set(&mz_active_rules, 0);
    atomic_set(&mz_active_dirs, 0);
    atomic_set(&mz_active_uids, 0);
    static_branch_disable(&mountzero_active_rules);
    static_branch_disable(&mountzero_active_dirs);
    static_branch_disable(&mountzero_active_uids);
    INIT_LIST_HEAD(&mountzero_private_dirs_list);
    synchronize_rcu();

    list_for_each_entry_safe(dir_node, tmp_dir, &dir_victims, private_list) {
        kfree(dir_node->dir_path);
        kmem_cache_free(mz_dir_cachep, dir_node);
    }
    list_for_each_entry_safe(rule, tmp_rule, &rule_victims, list) {
        kfree(rule->virtual_path);
        kfree(rule->real_path);
        kmem_cache_free(mz_rule_cachep, rule);
    }
    hlist_for_each_entry_safe(uid_node, hlist_tmp, &uid_victims, node) {
        kmem_cache_free(mz_uid_cachep, uid_node);
    }
}


/*** IOCTL Interface (original MountZero compat) ***/

static long mountzero_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {

	case MOUNTZERO_IOC_ADD_REDIRECT: {
		struct mz_ioctl_rule rule;
		int ret;
		if (copy_from_user(&rule, uarg, sizeof(rule)))
			return -EFAULT;
		rule.virtual_path[sizeof(rule.virtual_path) - 1] = '\0';
		rule.real_path[sizeof(rule.real_path) - 1] = '\0';
		ret = __mountzero_add_rule(rule.virtual_path, rule.real_path,
					   strlen(rule.virtual_path), strlen(rule.real_path),
					   rule.flags);
		if (ret) mz_err("IOCTL ADD failed: %s -> %s (err %d)\n",
				 rule.virtual_path, rule.real_path, ret);
		else mz_info("IOCTL ADD: %s -> %s\n", rule.virtual_path, rule.real_path);
		return ret;
	}

	case MOUNTZERO_IOC_DEL_REDIRECT: {
		struct mz_ioctl_path ipath;
		struct mz_inode_node *inode_node;
		struct mountzero_dir_node *dir;
		struct hlist_node *tmp_d;
		struct mountzero_rule *rule, *tmp_r;
		LIST_HEAD(r_victims);
		HLIST_HEAD(d_victims);
		if (copy_from_user(&ipath, uarg, sizeof(ipath)))
			return -EFAULT;
		ipath.virtual_path[sizeof(ipath.virtual_path) - 1] = '\0';
		mutex_lock(&mountzero_write_mutex);
		__mountzero_del_rule(ipath.virtual_path, strlen(ipath.virtual_path),
				     &r_victims, &d_victims);
		mutex_unlock(&mountzero_write_mutex);
		if (list_empty(&r_victims)) return -ENOENT;
		synchronize_rcu();
		hlist_for_each_entry_safe(inode_node, tmp_d, &d_victims, node) {
			dir = container_of(inode_node, struct mountzero_dir_node, dir);
			kfree(dir->dir_path);
			kmem_cache_free(mz_dir_cachep, dir);
		}
		list_for_each_entry_safe(rule, tmp_r, &r_victims, list) {
			mz_info("IOCTL DEL: %s\n", rule->virtual_path);
			kfree(rule->virtual_path);
			kfree(rule->real_path);
			kmem_cache_free(mz_rule_cachep, rule);
		}
		return 0;
	}

	case MOUNTZERO_IOC_CLEAR:
		mutex_lock(&mountzero_write_mutex);
		__mountzero_clear_all();
		mutex_unlock(&mountzero_write_mutex);
		mz_info("IOCTL CLEAR: all rules removed\n");
		return 0;

	case MOUNTZERO_IOC_LIST: {
		struct mz_ioctl_list klist;
		struct mountzero_rule *rule;
		int off = 0, cnt = 0;
		if (copy_from_user(&klist, uarg, sizeof(klist)))
			return -EFAULT;
		memset(klist.entries, 0, sizeof(klist.entries));
		rcu_read_lock();
		list_for_each_entry_rcu(rule, &mountzero_rules_list, list) {
			int vlen = strlen(rule->virtual_path);
			int rlen = strlen(rule->real_path);
			int need = vlen + 4 + rlen + 2;
			if (off + need < (int)sizeof(klist.entries)) {
				memcpy(klist.entries + off, rule->virtual_path, vlen);
				off += vlen;
				klist.entries[off++] = ' ';
				klist.entries[off++] = '-';
				klist.entries[off++] = '>';
				klist.entries[off++] = ' ';
				memcpy(klist.entries + off, rule->real_path, rlen);
				off += rlen;
				klist.entries[off++] = '\n';
				cnt++;
			}
		}
		rcu_read_unlock();
		klist.count = cnt;
		if (copy_to_user(uarg, &klist, sizeof(klist)))
			return -EFAULT;
		return 0;
	}

	case MOUNTZERO_IOC_BLOCK_UID: {
		unsigned int uid;
		struct mountzero_uid_node *entry;
		if (copy_from_user(&uid, uarg, sizeof(uid)))
			return -EFAULT;
		if (mountzero_is_uid_blocked(uid)) return -EEXIST;
		entry = kmem_cache_alloc(mz_uid_cachep, GFP_KERNEL);
		if (!entry) return -ENOMEM;
		entry->uid = uid;
		mutex_lock(&mountzero_write_mutex);
		hash_add_rcu(mountzero_uid_ht, &entry->node, uid);
		atomic_inc(&mz_active_uids);
		if (atomic_read(&mz_active_uids) == 1) static_branch_enable(&mountzero_active_uids);
		mutex_unlock(&mountzero_write_mutex);
		mz_info("IOCTL BLOCK_UID: %u\n", uid);
		return 0;
	}

	case MOUNTZERO_IOC_UNBLOCK_UID: {
		unsigned int uid;
		struct mountzero_uid_node *entry;
		struct hlist_node *tmp;
		int bkt;
		bool found = false;
		if (copy_from_user(&uid, uarg, sizeof(uid)))
			return -EFAULT;
		mutex_lock(&mountzero_write_mutex);
		hash_for_each_safe(mountzero_uid_ht, bkt, tmp, entry, node) {
			if (entry->uid == uid) {
				hash_del_rcu(&entry->node);
				found = true;
				break;
			}
		}
		if (atomic_read(&mz_active_uids) > 0) {
			atomic_dec(&mz_active_uids);
			if (atomic_read(&mz_active_uids) == 0)
				static_branch_disable(&mountzero_active_uids);
		}
		mutex_unlock(&mountzero_write_mutex);
		if (found) {
			synchronize_rcu();
			kmem_cache_free(mz_uid_cachep, entry);
		}
		mz_info("IOCTL UNBLOCK_UID: %u\n", uid);
		return found ? 0 : -ENOENT;
	}

	default:
		return -ENOTTY;
	}
}

static const struct file_operations mountzero_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = mountzero_ioctl,
};

static struct miscdevice mountzero_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "mountzero",
	.fops  = &mountzero_fops,
};

/*** Sysfs interface (original MountZero compat) ***/

static struct kobject *mountzero_kobj;

static ssize_t version_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	return sprintf(buf, "%d\n", MOUNTZERO_VERSION);
}
static struct kobj_attribute version_attr = __ATTR_RO(version);

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	return sprintf(buf, "enabled\n");
}
static struct kobj_attribute status_attr = __ATTR_RO(status);

static int __init mountzero_init(void) {
	int ret;

	hash_init(mountzero_rules_ht);
	hash_init(mountzero_basenames_ht);
	hash_init(mountzero_uid_ht);
	hash_init(mountzero_inodes_ht);

	mz_rule_cachep = kmem_cache_create("mz_rules", sizeof(struct mountzero_rule), 0, SLAB_HWCACHE_ALIGN, NULL);
	mz_dir_cachep = kmem_cache_create("mz_dirs", sizeof(struct mountzero_dir_node), 0, SLAB_HWCACHE_ALIGN, NULL);
	mz_uid_cachep = kmem_cache_create("mz_uids", sizeof(struct mountzero_uid_node), 0, SLAB_HWCACHE_ALIGN, NULL);

	if (!mz_rule_cachep || !mz_dir_cachep || !mz_uid_cachep) {
		mz_err("Failed to allocate memory slab caches\n");
		if (mz_rule_cachep) kmem_cache_destroy(mz_rule_cachep);
		if (mz_dir_cachep) kmem_cache_destroy(mz_dir_cachep);
		if (mz_uid_cachep) kmem_cache_destroy(mz_uid_cachep);
		return -ENOMEM;
	}

	ret = misc_register(&mountzero_dev);
	if (ret) {
		mz_err("Failed to register misc device (err: %d)\n", ret);
		kmem_cache_destroy(mz_rule_cachep);
		kmem_cache_destroy(mz_dir_cachep);
		kmem_cache_destroy(mz_uid_cachep);
		return ret;
	}

	mountzero_kobj = kobject_create_and_add("mountzero", kernel_kobj);
	if (mountzero_kobj) {
		if (sysfs_create_file(mountzero_kobj, &version_attr.attr))
			mz_warn("Failed to create version sysfs entry\n");
		if (sysfs_create_file(mountzero_kobj, &status_attr.attr))
			mz_warn("Failed to create status sysfs entry\n");
	}

	mz_info("Loaded successfully (IOCTL: /dev/mountzero)\n");
	return 0;
}

fs_initcall(mountzero_init);
