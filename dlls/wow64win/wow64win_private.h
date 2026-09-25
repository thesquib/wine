/*
 * WoW64 private definitions
 *
 * Copyright 2021 Alexandre Julliard
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

#ifndef __WOW64WIN_PRIVATE_H
#define __WOW64WIN_PRIVATE_H

#include "../win32u/win32syscalls.h"
#include "ntuser.h"

#define SYSCALL_ENTRY(id,name,_args) extern NTSTATUS WINAPI wow64_ ## name( UINT *args );
ALL_SYSCALLS32
#undef SYSCALL_ENTRY

extern ntuser_callback user_callbacks[];

struct object_attr64
{
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      str;
    SECURITY_DESCRIPTOR sd;
};

typedef struct
{
    ULONG Length;
    ULONG RootDirectory;
    ULONG ObjectName;
    ULONG Attributes;
    ULONG SecurityDescriptor;
    ULONG SecurityQualityOfService;
} OBJECT_ATTRIBUTES32;

/* PMW_VCPU: in a vCPU-mode WoW64 process the 32-bit address space lives at host BASE + p, with BASE 4 GiB aligned and
 * TEB32 inside the window, so BASE is what TEB32 aligns down to. Wherever the 32-bit space sits at its own addresses
 * (Windows, CrossOver, Linux Wine) BASE is 0 and everything below is the plain zero extension.
 * ULongToPtr/UlongToPtr/get_ptr therefore widen an ADDRESS: 0 stays NULL, anything else becomes BASE + p. A value that
 * only travels in a pointer-typed slot (an atom, a flag, an opaque key) must use wow64_value(), never the widening. */
static inline ULONG_PTR wow64_base(void)
{
    TEB *teb = NtCurrentTeb();
    return teb->WowTebOffset ? ((ULONG_PTR)teb + teb->WowTebOffset) & ~(ULONG_PTR)0xffffffff : 0;
}
static inline void *wow64_ptr( ULONG p ) { return p ? (void *)(wow64_base() + p) : NULL; }
static inline void *wow64_value( ULONG v ) { return (void *)(ULONG_PTR)v; }
#undef ULongToPtr
#undef UlongToPtr
#define ULongToPtr(ul) wow64_ptr(ul)
#define UlongToPtr(ul) wow64_ptr(ul)

/* a string address or an atom/resource id (IS_INTRESOURCE): a value below 0x10000 is never an address, so it is not widened */
static inline void *wow64_str_or_atom( ULONG v ) { return v < 0x10000 ? wow64_value( v ) : wow64_ptr( v ); }

static inline ULONG get_ulong( UINT **args ) { return *(*args)++; }
static inline HANDLE get_handle( UINT **args ) { return LongToHandle( *(*args)++ ); }
static inline void *get_ptr( UINT **args ) { return ULongToPtr( *(*args)++ ); }
static inline void *get_str( UINT **args ) { return wow64_str_or_atom( *(*args)++ ); }

static inline void **addr_32to64( void **addr, ULONG *addr32 )
{
    if (!addr32) return NULL;
    *addr = ULongToPtr( *addr32 );
    return addr;
}

static inline SIZE_T *size_32to64( SIZE_T *size, ULONG *size32 )
{
    if (!size32) return NULL;
    *size = *size32;
    return size;
}

static inline void put_addr( ULONG *addr32, void *addr )
{
    if (addr32) *addr32 = PtrToUlong( addr );
}

static inline void put_size( ULONG *size32, SIZE_T size )
{
    if (size32) *size32 = min( size, MAXDWORD );
}

static inline UNICODE_STRING *unicode_str_32to64( UNICODE_STRING *str, const UNICODE_STRING32 *str32 )
{
    if (!str32) return NULL;
    str->Length = str32->Length;
    str->MaximumLength = str32->MaximumLength;
    str->Buffer = wow64_str_or_atom( str32->Buffer );  /* a class name is an atom when Length is 0 */
    return str;
}

static inline SECURITY_DESCRIPTOR *secdesc_32to64( SECURITY_DESCRIPTOR *out, const SECURITY_DESCRIPTOR *in )
{
    /* relative descr has the same layout for 32 and 64 */
    const SECURITY_DESCRIPTOR_RELATIVE *sd = (const SECURITY_DESCRIPTOR_RELATIVE *)in;

    if (!in) return NULL;
    out->Revision = sd->Revision;
    out->Sbz1     = sd->Sbz1;
    out->Control  = sd->Control & ~SE_SELF_RELATIVE;
    if (sd->Control & SE_SELF_RELATIVE)
    {
        if (sd->Owner) out->Owner = (PSID)((BYTE *)sd + sd->Owner);
        if (sd->Group) out->Group = (PSID)((BYTE *)sd + sd->Group);
        if ((sd->Control & SE_SACL_PRESENT) && sd->Sacl) out->Sacl = (PSID)((BYTE *)sd + sd->Sacl);
        if ((sd->Control & SE_DACL_PRESENT) && sd->Dacl) out->Dacl = (PSID)((BYTE *)sd + sd->Dacl);
    }
    else
    {
        out->Owner = ULongToPtr( sd->Owner );
        out->Group = ULongToPtr( sd->Group );
        if (sd->Control & SE_SACL_PRESENT) out->Sacl = ULongToPtr( sd->Sacl );
        if (sd->Control & SE_DACL_PRESENT) out->Dacl = ULongToPtr( sd->Dacl );
    }
    return out;
}

static inline OBJECT_ATTRIBUTES *objattr_32to64( struct object_attr64 *out, const OBJECT_ATTRIBUTES32 *in )
{
    memset( out, 0, sizeof(*out) );
    if (!in) return NULL;
    if (in->Length != sizeof(*in)) return &out->attr;

    out->attr.Length = sizeof(out->attr);
    out->attr.RootDirectory = LongToHandle( in->RootDirectory );
    out->attr.Attributes = in->Attributes;
    out->attr.ObjectName = unicode_str_32to64( &out->str, ULongToPtr( in->ObjectName ));
    out->attr.SecurityQualityOfService = ULongToPtr( in->SecurityQualityOfService );
    out->attr.SecurityDescriptor = secdesc_32to64( &out->sd, ULongToPtr( in->SecurityDescriptor ));
    return &out->attr;
}

static inline void set_last_error32( DWORD err )
{
    TEB *teb = NtCurrentTeb();
    TEB32 *teb32 = (TEB32 *)((char *)teb + teb->WowTebOffset);
    teb32->LastErrorValue = err;
}

#endif /* __WOW64WIN_PRIVATE_H */
