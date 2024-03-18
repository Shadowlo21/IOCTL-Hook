#include "driver.h"

#define DVR_DEVICE_FILE (L"\\\\.\\MagicianSataModeReader") 

DriverClass::DriverClass()
{
	/**/
}
NTSTATUS DriverClass::send_serivce(ULONG ioctl_code, LPVOID io, DWORD size)
{
	if (DRIVERHANDLE == INVALID_HANDLE_VALUE)
		return STATUS_DEVICE_DOES_NOT_EXIST;

	if (!DeviceIoControl(DRIVERHANDLE, ioctl_code, io, size, nullptr, 0, NULL, NULL))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}
void DriverClass::AttachToProcess(DWORD pid)
{
	ProcID = pid;
}
NTSTATUS DriverClass::read_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
	rw req = { 0 };

	req.process_id = ProcID;
	req.address = reinterpret_cast<ULONGLONG>(base);
	req.buffer = reinterpret_cast<ULONGLONG>(buffer);
	req.size = (uint64_t)size;
	req.write = FALSE;

	return send_serivce(code_rw, &req, sizeof(req));
}
NTSTATUS DriverClass::write_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
	rw req = { 0 };

	req.process_id = ProcID;
	req.address = reinterpret_cast<ULONGLONG>(base);
	req.buffer = reinterpret_cast<ULONGLONG>(buffer);
	req.size = (uint64_t)size;
	req.write = TRUE;

	return send_serivce(code_rw, &req, sizeof(req));
}
NTSTATUS DriverClass::protect_memory_ex(uint64_t base, uint64_t size, PDWORD protection)
{
	pm req = { 0 };

	req.ProcessId = ProcID;
	req.Address = (PVOID)base;
	req.Size = size;
	req.InOutProtect = protection;

	return send_serivce(code_protect, &req, sizeof(req));
}
PVOID DriverClass::alloc_memory_ex(DWORD size, DWORD protect)
{
	PVOID p_out_address = NULL;
	am req = { 0 };

	req.ProcessId = ProcID;
	req.OutAddress = reinterpret_cast<ULONGLONG*>(&p_out_address);
	req.Size = size;
	req.Protect = protect;

	send_serivce(code_allocate, &req, sizeof(req));

	return p_out_address;
}
NTSTATUS DriverClass::free_memory_ex(PVOID address)
{
	fm req = { 0 };

	req.ProcessId = ProcID;
	req.Address = address;

	return send_serivce(code_free, &req, sizeof(req));
}
void DriverClass::DriverHANDLE()
{
	DRIVERHANDLE = CreateFileW(DVR_DEVICE_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}
DriverClass::~DriverClass()
{
	CloseHandle(DRIVERHANDLE);
}
DriverClass& DriverClass::singleton()
{
	static DriverClass p_object;
	return p_object;
}