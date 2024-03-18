#include "includes/includes.hpp"

#include "engine/utilities/oxorany/oxorany_include.h"
#include "engine/utilities/clean/clean.hpp"
#include "engine/utilities/utilities.hpp"

#pragma comment( linker, "/merge:.pdata=.rdata" )
#pragma comment( linker, "/merge:.rdata=.text" )

#define find_base_address CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1588, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define read_process_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1589, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define write_process_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1590, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define protect_process_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1591, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define allocate_process_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1592, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define free_process_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1593, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

PVOID get_image_base( PBASE_REQUEST request )
{
    if ( !request->ProcessId )
        return 0;
    
    PEPROCESS temp_process;
    if ( !NT_SUCCESS( PsLookupProcessByProcessId( ( HANDLE )request->ProcessId, &temp_process ) ) )
        return 0;

    PVOID image_base = PsGetProcessSectionBaseAddress( temp_process );
    if ( !image_base ) 
        return 0;

    RtlCopyMemory(request->OutAddress, image_base, sizeof(image_base));

    ObDereferenceObject( temp_process );

    return image_base;
}

NTSTATUS hooked_ioctl( PDEVICE_OBJECT obj, PIRP irp ) {
    UNREFERENCED_PARAMETER( obj );

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = sizeof( RW_REQUEST );

    const auto stack = IoGetCurrentIrpStackLocation( irp );

    size_t size;
    if ( stack ) {
            /* receving ioctl codes from usermode */
            auto ioctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
            if ( ioctl_code == find_base_address ) {
                /* find base address */
                PBASE_REQUEST req = (PBASE_REQUEST)(irp->AssociatedIrp.SystemBuffer);
                auto ret = get_image_base( req );
            } 
            if ( ioctl_code == read_process_memory ) {
                /* read process memory */
                PRW_REQUEST req = (PRW_REQUEST)(irp->AssociatedIrp.SystemBuffer);
                utilities::memory::ReadMemory(req);
            }
            if ( ioctl_code == write_process_memory ) {
                /* write process memory */
                PRW_REQUEST req = (PRW_REQUEST)(irp->AssociatedIrp.SystemBuffer);
                utilities::memory::WriteMemory(req);
            }
            if (ioctl_code == allocate_process_memory) {
                /* allocate process memory */
                PALLOCATE_REQUEST req = (PALLOCATE_REQUEST)(irp->AssociatedIrp.SystemBuffer);
                utilities::memory::AllocMemory(req);
            }
            if (ioctl_code == protect_process_memory) {
                /* allocate process memory */
                PPROTECT_REQUEST req = (PPROTECT_REQUEST)(irp->AssociatedIrp.SystemBuffer);
                utilities::memory::ProtectMemory(req);
            }
            if (ioctl_code == free_process_memory) {
                /* allocate process memory */
                PFREE_REQUEST req = (PFREE_REQUEST)(irp->AssociatedIrp.SystemBuffer);
                utilities::memory::FreeMemory(req);
            }
    }

    IoCompleteRequest( irp, IO_NO_INCREMENT );

    return irp->IoStatus.Status;
}

 NTSTATUS driver_entry( )
 {
    /* find vulnerable driver */
    const auto driver = utilities::kernel::get_module( "magdrvamd64.sys" );
    if ( !driver )
        return o( STATUS_FAILED_DRIVER_ENTRY );

    /* find ioctl communication of vulnerable driver */
    const auto ioctl_start = utilities::kernel::pattern::find_pattern( driver, "\x48\x89\x54\x24\x00\x48\x89\x4C\x24\x00\x48\x83\xEC\x68", "xxxx?xxxx?xxxx" );
    if ( !ioctl_start )
        return o( STATUS_FAILED_DRIVER_ENTRY );

    /* our address of hooked function */
    const auto to_hook = reinterpret_cast< uintptr_t >( &hooked_ioctl );

    char shellcode_final[ ] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    char mov_rax[ ] = { 0x48, 0x44 }; /* mov eax, xxx */
    char jmp_rax[ ] = { 0xFF, 0xC1 }; /* call eax */

    /* cleaning shellcode */
    RtlSecureZeroMemory( &shellcode_final, sizeof( shellcode_final ) );

    memcpy( ( PVOID )( ( ULONG_PTR )shellcode_final ), &mov_rax, sizeof( mov_rax ) );
    memcpy( ( PVOID )( ( ULONG_PTR )shellcode_final + sizeof( mov_rax ) ), &to_hook, sizeof( void* ) );
    memcpy( ( PVOID )( ( ULONG_PTR )shellcode_final + sizeof( mov_rax ) + sizeof( void* ) ), &jmp_rax, sizeof( jmp_rax ) );

    /* writing our shellcode into ioctl of vulnerable driver */
    utilities::kernel::write_to_rw_memory( ( void* )ioctl_start, &shellcode_final, sizeof( shellcode_final ) );

    /* done */
    return o( STATUS_SUCCESS );
 }