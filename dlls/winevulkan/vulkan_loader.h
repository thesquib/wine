/* Wine Vulkan ICD private data structures
 *
 * Copyright 2017 Roderick Colenbrander
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_VULKAN_LOADER_H
#define __WINE_VULKAN_LOADER_H

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include <stdarg.h>
#include <stdlib.h>
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ntuser.h"
#include "wine/debug.h"
#include "wine/vulkan.h"
#include "wine/vulkan_driver.h"
#include "wine/unixlib.h"
#include "wine/list.h"

#include "loader_thunks.h"

/* Magic value defined by Vulkan ICD / Loader spec */
#define VULKAN_ICD_MAGIC_VALUE 0x01CDC0DE

struct vk_command_pool
{
    struct vulkan_client_object obj;
    struct list command_buffers;
};

static inline struct vk_command_pool *command_pool_from_handle(VkCommandPool handle)
{
    return (struct vk_command_pool *)(uintptr_t)handle;
}

struct VkCommandBuffer_T
{
    struct vulkan_client_object obj;
    struct list pool_link;
    /* PMW_VK_BATCH (loader.c): queued vkCmd* records, replayed in order by one unix call */
    BYTE *batch;
    SIZE_T batch_used, batch_size, batch_data;
};

/* PROTON_DARWIN PMW_VK_BATCH: a queued call is a header, the call's params struct and the data its pointers were
 * redirected to, each 8-aligned; unix_batch_execute runs the records in order through the unix call table. */
struct vk_batch_header
{
    UINT32 code;
    UINT32 size;  /* the whole record */
};

struct batch_execute_params
{
    UINT64 data;
    UINT64 size;
};

#define VK_BATCH_ALIGN(x) (((SIZE_T)(x) + 7) & ~(SIZE_T)7)

extern BOOL vk_batch_enabled;
void *vk_batch_begin(VkCommandBuffer buffer, UINT32 code, const void *params, SIZE_T params_size, SIZE_T extra);
const void *vk_batch_data(VkCommandBuffer buffer, const void *src, SIZE_T size);
void vk_batch_flush_slow(VkCommandBuffer buffer);
void vk_batch_flush_pool(VkCommandPool pool);

/* every element's pNext is NULL (a queued copy keeps no chain), or the array is absent */
static inline BOOL vk_batch_chain_free(const void *array, SIZE_T count, SIZE_T stride)
{
    const BYTE *p = array;
    SIZE_T i;

    if (!p) return TRUE;
    for (i = 0; i < count; i++, p += stride)
        if (((const VkBaseInStructure *)p)->pNext) return FALSE;
    return TRUE;
}

static inline void vk_batch_flush(VkCommandBuffer buffer)
{
    if (buffer && buffer->batch_used) vk_batch_flush_slow(buffer);
}

struct vulkan_func
{
    const char *name;
    void *func;
};

void *wine_vk_get_device_proc_addr(const char *name);
void *wine_vk_get_phys_dev_proc_addr(const char *name);
void *wine_vk_get_instance_proc_addr(const char *name);

struct init_params
{
    UINT64 call_vulkan_debug_report_callback;
    UINT64 call_vulkan_debug_utils_callback;
    struct vulkan_instance_extensions *extensions;
};

/* debug callbacks params */

struct debug_utils_label
{
    UINT32 label_name_len;
    float color[4];
};

struct debug_utils_object
{
    UINT32 object_type;
    UINT64 object_handle;
    UINT32 object_name_len;
};

struct debug_device_address_binding
{
    UINT32 flags;
    UINT64 base_address;
    UINT64 size;
    UINT32 binding_type;
};

struct wine_vk_debug_utils_params
{
    struct dispatch_callback_params dispatch;
    UINT64 user_callback; /* client pointer */
    UINT64 user_data; /* client pointer */

    UINT32 severity;
    UINT32 message_types;
    UINT32 flags;
    UINT32 message_id_number;

    UINT32 message_id_name_len;
    UINT32 message_len;
    UINT32 queue_label_count;
    UINT32 cmd_buf_label_count;
    UINT32 object_count;

    UINT8 has_address_binding;
    struct debug_device_address_binding address_binding;
};

struct wine_vk_debug_report_params
{
    struct dispatch_callback_params dispatch;
    UINT64 user_callback; /* client pointer */
    UINT64 user_data; /* client pointer */

    UINT32 flags;
    UINT32 object_type;
    UINT64 object_handle;
    UINT64 location;
    UINT32 code;
    UINT32 layer_len;
    UINT32 message_len;
};

struct is_available_instance_function_params
{
    VkInstance instance;
    const char *name;
};

struct is_available_device_function_params
{
    VkDevice device;
    const char *name;
};

#define UNIX_CALL(code, params) WINE_UNIX_CALL(unix_ ## code, params)
#define UNIX_CALL_CHECKED(code, params)                           \
    do {                                                          \
        NTSTATUS status = UNIX_CALL(code, params);                \
        if (status)                                               \
        {                                                         \
            ERR("Exception %#lx in Unix call.\n", status);        \
            ExitProcess(3);                                       \
        }                                                         \
    } while (0)

#endif /* __WINE_VULKAN_LOADER_H */
