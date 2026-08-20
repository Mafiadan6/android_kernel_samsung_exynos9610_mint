#ifndef _LINUX_MOUNTZERO_H
#define _LINUX_MOUNTZERO_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/jump_label.h>

#define MOUNTZERO_VERSION    10
#define MOUNTZERO_HASH_BITS  12
#define MOUNTZERO_UID_HASH_BITS 4
#define MZ_FLAG_IS_DIR      (1 << 1)
#define MZ_INO_TYPE_REAL    (1 << 0)
#define MZ_INO_TYPE_VIRTUAL (1 << 1)
#define MZ_INO_TYPE_DIR     (1 << 2)

static DEFINE_HASHTABLE(mountzero_rules_ht,     MOUNTZERO_HASH_BITS);
static DEFINE_HASHTABLE(mountzero_inodes_ht,    MOUNTZERO_HASH_BITS);
static DEFINE_HASHTABLE(mountzero_basenames_ht, MOUNTZERO_HASH_BITS);
static DEFINE_HASHTABLE(mountzero_uid_ht,       MOUNTZERO_UID_HASH_BITS);
static LIST_HEAD(mountzero_rules_list);
static LIST_HEAD(mountzero_private_dirs_list);
static DEFINE_MUTEX(mountzero_write_mutex);

struct mz_inode_node {
    struct hlist_node node;
    unsigned long ino;
    dev_t dev;
    u8 type;
    u16 len;
};

struct mountzero_child_name {
    unsigned long fake_ino;
    u16 name_len;
    u8 d_type;
    char name[256];
};

struct mz_child_array {
    atomic_t refcnt;
    u32 num_children;
    struct rcu_head rcu;
    struct mountzero_child_name entries[]; /* Flexible array member */
};

struct mountzero_dir_node {
    struct mz_inode_node dir;
    struct list_head private_list;
    struct mz_child_array __rcu *child_array; 
    char *dir_path;
    bool is_private;
};

struct mountzero_rule {
    struct list_head list;
    struct mz_inode_node real_node; 
    struct mz_inode_node virt_node;
    struct hlist_node vpath_node;
    struct hlist_node basename_node;
    struct mountzero_dir_node *parent_dir;
    char *virtual_path;
    char *real_path;
    const char *basename;
    u32 v_fs_type;
    u32 v_hash;
    u32 b_hash;
    u16 b_len;
    u8  flags;
};

struct mountzero_uid_node {
    struct hlist_node node;
    uid_t uid;
};

/* VFS Hook Prototypes */
char *mountzero_handle_dpath(const struct path *path, char *buf, int buflen);
int mountzero_handle_permission(struct inode *inode, int mask);
struct filename *mountzero_handle_getname(struct filename *name);
int mountzero_handle_iterate_dir(struct file *file, struct dir_context *ctx);
int mountzero_handle_getattr(int ret, const struct path *path, struct kstat *stat);
void mountzero_spoof_statfs(const struct path *path, struct kstatfs *buf);
bool mountzero_spoof_mmap_metadata(struct inode *inode, dev_t *dev, unsigned long *ino);

/* ========================================================================= */
/* IOCTL INTERFACE (original MountZero compat) */
/* ========================================================================= */

#define MOUNTZERO_IOC_MAGIC 'Z'

struct mz_ioctl_rule {
    char virtual_path[256];
    char real_path[256];
    unsigned int flags;
};

struct mz_ioctl_path {
    char virtual_path[256];
};

struct mz_ioctl_list {
    char entries[4096];
    int count;
};

#define MOUNTZERO_IOC_ADD_REDIRECT   _IOW(MOUNTZERO_IOC_MAGIC, 10, struct mz_ioctl_rule)
#define MOUNTZERO_IOC_DEL_REDIRECT   _IOW(MOUNTZERO_IOC_MAGIC, 11, struct mz_ioctl_path)
#define MOUNTZERO_IOC_CLEAR          _IO(MOUNTZERO_IOC_MAGIC, 100)
#define MOUNTZERO_IOC_LIST           _IOWR(MOUNTZERO_IOC_MAGIC, 101, struct mz_ioctl_list)
#define MOUNTZERO_IOC_BLOCK_UID      _IOW(MOUNTZERO_IOC_MAGIC, 80, unsigned int)
#define MOUNTZERO_IOC_UNBLOCK_UID    _IOW(MOUNTZERO_IOC_MAGIC, 81, unsigned int)

/* Application UID start */
#define AID_APP_START 10000

#endif /* _LINUX_MOUNTZERO_H */
