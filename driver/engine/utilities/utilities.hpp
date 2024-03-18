#include "encrypt/encrypt.hpp"
#include "kernel/kernel.hpp"
#include "clean/clean.hpp"
#include "crt/crt.hpp"
uintptr_t saved_dirbase = 0;
bool already_attached = false;

struct virt_addr_t {
	union {
		uint64_t value;
		struct {
			uint64_t offset : 12;
			uint64_t pt_index : 9;
			uint64_t pd_index : 9;
			uint64_t pdpt_index : 9;
			uint64_t pml4_index : 9;
			uint64_t reserved : 16;
		};	
	};
};

//0x8 bytes (sizeof)
struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Dirty1 : 1;                                                     //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Accessed : 1;                                                   //0x0
	ULONGLONG Dirty : 1;                                                      //0x0
	ULONGLONG LargePage : 1;                                                  //0x0
	ULONGLONG Global : 1;                                                     //0x0
	ULONGLONG CopyOnWrite : 1;                                                //0x0
	ULONGLONG Unused : 1;                                                     //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG PageFrameNumber : 40;                                           //0x0
	ULONGLONG ReservedForSoftware : 4;                                        //0x0
	ULONGLONG WsleAge : 4;                                                    //0x0
	ULONGLONG WsleProtection : 3;                                             //0x0
	ULONGLONG NoExecute : 1;                                                  //0x0
};

//0x8 bytes (sizeof)
struct _MMPTE
{
	union
	{
		struct _MMPTE_HARDWARE Hard;                                        //0x0
	} u;                                                                    //0x0
};

namespace utilities {
	namespace physical {
		NTSTATUS read_physical_address( PVOID target_address, PVOID lp_buffer, SIZE_T size, SIZE_T* bytes_read ) {
			MM_COPY_ADDRESS copy = { 0 };
			copy.PhysicalAddress.QuadPart = ( LONGLONG )target_address;
			return MmCopyMemory( lp_buffer, copy, size, o( MM_COPY_MEMORY_PHYSICAL ), bytes_read );
		}

		uint64_t translate_linear_address( uint64_t directory_table_base, uint64_t virtual_address ) {
			static const uintptr_t PMASK = ( o( ~0xfull ) << o( 8 ) ) & o( 0xfffffffffull );

			directory_table_base &= o( ~0xf );

			uintptr_t page_offset = virtual_address & ~( o( ~0ul ) << o( 12 ) );
			uintptr_t pte = ( ( virtual_address >> o( 12 ) ) & ( o( 0x1ffll ) ) );
			uintptr_t pt = ( ( virtual_address >> o( 21 ) ) & ( o( 0x1ffll ) ) );
			uintptr_t pd = ( ( virtual_address >> o( 30 ) ) & ( o( 0x1ffll ) ) );
			uintptr_t pdp = ( ( virtual_address >> o( 39 ) ) & ( o( 0x1ffll ) ) );

			size_t readsize = o( 0 );
			uintptr_t pdpe = o( 0 );

			read_physical_address( PVOID( directory_table_base + o( 8 ) * pdp ), &pdpe, sizeof( pdpe ), &readsize );
			if ( ~pdpe & 1 ) {
				return 0;
			}

			uintptr_t pde = 0;
			read_physical_address( PVOID( ( pdpe & PMASK ) + o( 8 ) * pd ), &pde, sizeof( pde ), &readsize );

			if ( ~pde & o( 1 ) ) {
				return o( 0 );
			}

			if ( pde & o( 0x80 ) ) {
				return ( pde & ( o( ~0ull ) << o( 42 ) >> o( 12 ) ) ) + ( virtual_address & ~( o( ~0ull ) << o( 30 ) ) );
			}

			uintptr_t pte_addr = o( 0 );
			read_physical_address( PVOID( ( pde & PMASK ) + o( 8 ) * pt ), &pte_addr, sizeof( pte_addr ), &readsize );

			if ( ~pte_addr & o( 1 ) ) {
				return o( 0 );
			}

			if ( pte_addr & o( 0x80 ) ) {
				return ( pte_addr & PMASK ) + ( virtual_address & ~( o( ~0ull ) << o( 21 ) ) );
			}

			virtual_address = o( 0 );
			read_physical_address( PVOID( ( pte_addr & PMASK ) + o( 8 ) * pte ), &virtual_address, sizeof( virtual_address ), &readsize );
			virtual_address &= PMASK;

			if ( !virtual_address ) {
				return o( 0 );
			}

			return virtual_address + page_offset;
		}

		NTSTATUS write_physical_address( PVOID target_address, PVOID lp_buffer, SIZE_T size, SIZE_T* bytes_written ) {
			if ( !target_address ) {
				return o( STATUS_UNSUCCESSFUL );
			}

			PHYSICAL_ADDRESS addr_to_write = { 0 };
			addr_to_write.QuadPart = LONGLONG( target_address );

			PVOID pmapped_mem = MmMapIoSpaceEx( addr_to_write, size, o( PAGE_READWRITE ) );
			if ( !pmapped_mem ) {
				return o( STATUS_UNSUCCESSFUL );
			}

			__movsb( PBYTE( pmapped_mem ), PBYTE( lp_buffer ), size );

			*bytes_written = size;
			MmUnmapIoSpace( pmapped_mem, size );

			return o( STATUS_SUCCESS );
		}

		NTSTATUS read_proc_memory( uint64_t dirbase, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read ) {
			if ( dirbase == 0 || !Address || !AllocatedBuffer || size == 0 || !read ) {
				return o( STATUS_INVALID_PARAMETER );
			}

			SIZE_T cur_offset = 0;
			SIZE_T total_size = size;
			NTSTATUS nt_ret = STATUS_SUCCESS;

			while ( total_size )
			{
				uint64_t cur_phys_address = physical::translate_linear_address( dirbase, ( ULONG64 )Address + cur_offset );
				if ( !cur_phys_address ) {
					return o( STATUS_UNSUCCESSFUL );
				}

				ULONG64 read_size = min( PAGE_SIZE - ( cur_phys_address & 0xFFF ), total_size );
				SIZE_T bytes_read = 0;

				nt_ret = physical::read_physical_address( ( PVOID )cur_phys_address, ( PVOID )( ( ULONG64 )AllocatedBuffer + cur_offset ), read_size, &bytes_read );

				total_size -= bytes_read;
				cur_offset += bytes_read;

				if ( nt_ret != o( STATUS_SUCCESS ) || bytes_read == 0 ) {
					break;
				}
			}

			*read = cur_offset;
			return nt_ret;
		}
#define win_1803 17134
#define win_1809 17763
#define win_1903 18362
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19569
#define win_21H1 20180
		INT32 get_winver() {
			
			RTL_OSVERSIONINFOW ver = { 0 };
			RtlGetVersion(&ver);
			switch (ver.dwBuildNumber)
			{
			case win_1803:
				return 0x0278;
				break;
			case win_1809:
				return 0x0278;
				break;
			case win_1903:
				return 0x0280;
				break;
			case win_1909:
				return 0x0280;
				break;
			case win_2004:
				return 0x0388;
				break;
			case win_20H2:
				return 0x0388;
				break;
			case win_21H1:
				return 0x0388;
				break;
			default:
				return 0x0388;
			}
		}
		uint64_t get_process_dirbase(PEPROCESS pprocess) {


			if (!pprocess) return 0;
			uintptr_t process_dirbase = *(uintptr_t*)((UINT8*)pprocess + 0x28);
			if (process_dirbase == 0)
			{
				ULONG user_diroffset = get_winver();
				process_dirbase = *(uintptr_t*)((UINT8*)pprocess + user_diroffset);
			}
			if ((process_dirbase >> 0x38) == 0x40)
			{
				if (!already_attached)
				{

					KAPC_STATE apc_state{};

					KeStackAttachProcess(pprocess, &apc_state);

					saved_dirbase = __readcr3();

					KeUnstackDetachProcess(&apc_state);
					already_attached = true;


				}
				if (saved_dirbase) return saved_dirbase;
			}
			return process_dirbase;


		}
	}

	namespace memory {
		//bool read( PDRIVER_REQUEST in ) {
		//	if ( !in->pid )
		//		return o( false );

		//	PEPROCESS temp_process;
		//	if ( !NT_SUCCESS( PsLookupProcessByProcessId( in->pid, &temp_process ) ) )
		//		return o( false );

		//	auto directory_table = physical::get_process_dirbase(temp_process);
		//	if ( !directory_table )
		//		return false;

		//	ObDereferenceObject( temp_process );
		//	
		//	uintptr_t physical_address = physical::translate_linear_address( directory_table, ( uintptr_t )in->address );
		//	if ( !physical_address ) 
		//		return o( false );

		//	uintptr_t final_size = min( PAGE_SIZE - ( physical_address & 0xFFF ), in->size );

		//	size_t bytes_trough = 0;
		//	physical::read_physical_address( ( PVOID )physical_address, in->buffer, final_size, &bytes_trough );

		//	return o( true );
		//}

		//bool write( PDRIVER_REQUEST in ) {
		//	if ( !in->pid )
		//		return o( false );

		//	PEPROCESS temp_process;
		//	if ( !NT_SUCCESS( PsLookupProcessByProcessId( in->pid, &temp_process ) ) )
		//		return false;

		//	auto directory_table = physical::get_process_dirbase(  temp_process  );
		//	if ( !directory_table )
		//		return false;

		//	ObDereferenceObject( temp_process );

		//	uintptr_t physical_address = physical::translate_linear_address( directory_table, ( uintptr_t )in->address );
		//	if ( !physical_address )
		//		return o( false );

		//	uintptr_t final_size = min( o( PAGE_SIZE ) - ( physical_address & o( 0xFFF ) ), in->size );

		//	size_t bytes_trough = 0;
		//	physical::write_physical_address( ( PVOID )physical_address, in->buffer, final_size, &bytes_trough );

		//	return o( true );
		//}

		// origbuffer = __readcr0()
		// __writecr0(0x0)

		// __writecr0(origbuffer)

		NTSTATUS ReadMemory(PRW_REQUEST Message) 
		{
			NTSTATUS Status = STATUS_SUCCESS;
			PEPROCESS Process = NULL;

			Status = PsLookupProcessByProcessId((HANDLE)Message->process_id, &Process);

			if (!NT_SUCCESS(Status)) {
				return Status;
			}

			SIZE_T Result = 0;

			__try {

				Status = MmCopyVirtualMemory(
					Process,
					(PVOID)Message->address,
					PsGetCurrentProcess(),
					(PVOID)Message->buffer,
					Message->size,
					KernelMode,
					&Result
				);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {

				Status = GetExceptionCode();
			}

			ObDereferenceObject(Process);

			return Status;
		}

		NTSTATUS WriteMemory(PRW_REQUEST Message)
		{
			NTSTATUS Status = STATUS_SUCCESS;
			PEPROCESS Process = NULL;

			Status = PsLookupProcessByProcessId((HANDLE)Message->process_id, &Process);

			if (!NT_SUCCESS(Status)) {
				return Status;
			}

			SIZE_T Result = 0;

			__try {

				Status = MmCopyVirtualMemory(
					PsGetCurrentProcess(),
					(PVOID)Message->buffer,
					Process,
					(PVOID)Message->address,
					Message->size,
					KernelMode,
					&Result
				);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {

				Status = GetExceptionCode();
			}

			ObDereferenceObject(Process);

			return Status;
		}

		BOOL
			SafeCopy(
				PVOID Dest,
				PVOID Src,
				SIZE_T Size
			) {
			SIZE_T returnSize = 0;
			if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), Src, PsGetCurrentProcess(), Dest, Size, KernelMode, &returnSize)) && returnSize == Size) {
				return TRUE;
			}

			return FALSE;
		}

		NTSTATUS ProtectMemory(PPROTECT_REQUEST Str) {
			PEPROCESS Process = NULL;
			NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Str->ProcessId, &Process);
			if (NT_SUCCESS(Status)) {
				DWORD Protect = NULL;
				SIZE_T ReturnSize = NULL;
				if (SafeCopy(&Protect, Str->InOutProtect, sizeof(Protect))) {
					SIZE_T Size = Str->Size;
					KeAttachProcess(Process);
					Status = ZwProtectVirtualMemory(NtCurrentProcess(), &Str->Address, &Size, Protect, &Protect);
					KeDetachProcess();
					SafeCopy(Str->InOutProtect, &Protect, sizeof(Protect));
				}
				else {
					Status = STATUS_ACCESS_VIOLATION;
				}

				ObDereferenceObject(Process);
			}
			return Status;
		}

		NTSTATUS AllocMemory(PALLOCATE_REQUEST Str) {
			PEPROCESS Process = NULL;
			NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Str->ProcessId, &Process);
			if (NT_SUCCESS(Status)) {
				PVOID Address = NULL;
				SIZE_T size = Str->Size;

				KeAttachProcess(Process);
				ZwAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &size, MEM_COMMIT | MEM_RESERVE, Str->Protect);
				KeDetachProcess();

				SafeCopy(Str->OutAddress, &Address, sizeof(Address));

				ObDereferenceObject(Process);
			}

			return Status;
		}

		NTSTATUS FreeMemory(PFREE_REQUEST Str) {
			PEPROCESS Process = NULL;
			NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Str->ProcessId, &Process);
			if (NT_SUCCESS(Status)) {
				SIZE_T Size = 0;

				KeAttachProcess(Process);
				ZwFreeVirtualMemory(NtCurrentProcess(), &Str->Address, &Size, MEM_RELEASE);
				KeDetachProcess();

				ObDereferenceObject(Process);
			}

			return Status;
		}

	}
}