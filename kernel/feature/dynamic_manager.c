#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/pid.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#endif
#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#include "manager/throne_tracker.h"
#include "compat/kernel_compat.h"
#include "dynamic_manager.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "ksu.h"

// Dynamic sign configuration
static struct dynamic_manager_config dynamic_manager = {
    .size = 0x300,
    .hash = "0000000000000000000000000000000000000000000000000000000000000000",
    .is_set = 0
};

static DEFINE_SPINLOCK(dynamic_manager_lock);

bool ksu_is_dynamic_manager_enabled(void)
{
    unsigned long flags;
    bool enabled;

    spin_lock_irqsave(&dynamic_manager_lock, flags);
    enabled = dynamic_manager.is_set;
    spin_unlock_irqrestore(&dynamic_manager_lock, flags);

    return enabled;
}

bool ksu_dynamic_manager_sign_matches(unsigned size, const char *sha256)
{
    unsigned long flags;
    bool matched;

    spin_lock_irqsave(&dynamic_manager_lock, flags);
    matched = dynamic_manager.is_set && size == dynamic_manager.size && strcmp(dynamic_manager.hash, sha256) == 0;
    spin_unlock_irqrestore(&dynamic_manager_lock, flags);
    return matched;
}

int ksu_handle_dynamic_manager(struct ksu_dynamic_manager_cmd *cmd)
{
    unsigned long flags;
    int ret = 0;
    int i;

    if (!cmd) {
        return -EINVAL;
    }

    switch (cmd->operation) {
    case DYNAMIC_MANAGER_OP_SET_SYNCHRONOUS:
    case DYNAMIC_MANAGER_OP_SET:
        if (cmd->size < 0x100 || cmd->size > 0x1000) {
            pr_err("invalid size: 0x%x\n", cmd->size);
            return -EINVAL;
        }

        // Validate hash format
        for (i = 0; i < 64; i++) {
            char c = cmd->hash[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                pr_err("invalid hash character at position %d: %c\n", i, c);
                return -EINVAL;
            }
        }

        spin_lock_irqsave(&dynamic_manager_lock, flags);

        if (dynamic_manager.is_set)
            ksu_unregister_manager_by_signature_index(KSU_SIGNATURE_INDEX_DYNAMIC_MANAGER);

        dynamic_manager.size = cmd->size;
        // userspace always put an char[64] to our
        // we just use memcpy to copy memory, and flag [64] to \0 by ourselves
        for (i = 0; i < 64; i++)
            dynamic_manager.hash[i] = tolower(cmd->hash[i]);
        dynamic_manager.hash[64] = '\0';

        dynamic_manager.is_set = 1;

        spin_unlock_irqrestore(&dynamic_manager_lock, flags);

        if (cmd->operation == DYNAMIC_MANAGER_OP_SET_SYNCHRONOUS)
            track_throne(TRACK_THRONE_FORCE_SEARCH_MGR | TRACK_THRONE_FORCE_SYNCHRONOUS);
        else
            track_throne(TRACK_THRONE_FORCE_SEARCH_MGR);
        pr_info("dynamic manager updated: size=0x%x, hash=%.16s\n", cmd->size, cmd->hash);
        break;

    case DYNAMIC_MANAGER_OP_GET:
        spin_lock_irqsave(&dynamic_manager_lock, flags);
        if (dynamic_manager.is_set) {
            cmd->size = dynamic_manager.size;

            // only copy [64] is enough, userspace will handle that
            memcpy(cmd->hash, dynamic_manager.hash, 64);
            ret = 0;
        } else {
            ret = -ENODATA;
        }
        spin_unlock_irqrestore(&dynamic_manager_lock, flags);
        break;
    case DYNAMIC_MANAGER_OP_WIPE:
        spin_lock_irqsave(&dynamic_manager_lock, flags);
        dynamic_manager.is_set = 0;
        spin_unlock_irqrestore(&dynamic_manager_lock, flags);
        ret = 0;
        ksu_unregister_manager_by_signature_index(KSU_SIGNATURE_INDEX_DYNAMIC_MANAGER);
        pr_info("dynamic manager kernel settings reseted");
        break;

    default:
        pr_err("Invalid dynamic manager operation: %d\n", cmd->operation);
        return -EINVAL;
    }

    return ret;
}
