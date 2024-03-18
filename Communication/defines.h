#pragma once

///////////////////////////////////////////////////////////
#define offset_io_mirrore   0x2338
#define file_device_mirrore 0x3009
///////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////
#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x72, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_allocate CTL_CODE(FILE_DEVICE_UNKNOWN, 0x73, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_protect CTL_CODE(FILE_DEVICE_UNKNOWN, 0x74, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_free CTL_CODE(FILE_DEVICE_UNKNOWN, 0x75, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
///////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////

typedef struct _rw {
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
} rw, * prw;

typedef struct _pm {
	INT32 ProcessId;
	PVOID Address;
	DWORD Size;
	PVOID InOutProtect;
} pm, * ppm;

typedef struct _am {
	INT32 ProcessId;
	DWORD Size;
	ULONGLONG Protect;
	ULONGLONG* OutAddress;
} am, * pam;

typedef struct _fm {
	INT32 ProcessId;
	PVOID Address;
} fm, * pfm;


typedef struct _ba {
	INT32 process_id;
	ULONGLONG* address;
} ba, * pba;//////////////

