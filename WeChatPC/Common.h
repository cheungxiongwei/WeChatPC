#pragma once
#include <Windows.h>
/*头文件声明*/
typedef LONG NTSTATUS;

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)   
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)   
#define STATUS_NOT_IMPLEMENTED          ((NTSTATUS)0xC0000002L)   
#define STATUS_INVALID_INFO_CLASS       ((NTSTATUS)0xC0000003L)   
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)  

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define CLOSEMUTEXNAME L"\Sessions\1\BaseNamedObjects\XAJHElementClient_Multiple_Instance_Tag_Name_0"

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,					// 0        Y        N
	SystemProcessorInformation,				// 1        Y        N
	SystemPerformanceInformation,			// 2        Y        N
	SystemTimeOfDayInformation,				// 3        Y        N
	SystemNotImplemented1,					// 4        Y        N
	SystemProcessesAndThreadsInformation,	// 5        Y        N
	SystemCallCounts,						// 6        Y        N
	SystemConfigurationInformation,			// 7        Y        N
	SystemProcessorTimes,					// 8        Y        N
	SystemGlobalFlag,						// 9        Y        Y
	SystemNotImplemented2,					// 10       Y        N
	SystemModuleInformation,				// 11       Y        N
	SystemLockInformation,					// 12       Y        N
	SystemNotImplemented3,					// 13       Y        N
	SystemNotImplemented4,					// 14       Y        N
	SystemNotImplemented5,					// 15       Y        N
	SystemHandleInformation,				// 16       Y        N
	SystemObjectInformation,				// 17       Y        N
	SystemPagefileInformation,				// 18       Y        N
	SystemInstructionEmulationCounts,		// 19       Y        N
	SystemInvalidInfoClass1,				// 20
	SystemCacheInformation,					// 21       Y        Y
	SystemPoolTagInformation,				// 22       Y        N
	SystemProcessorStatistics,				// 23       Y        N
	SystemDpcInformation,					// 24       Y        Y
	SystemNotImplemented6,					// 25       Y        N
	SystemLoadImage,						// 26       N        Y
	SystemUnloadImage,						// 27       N        Y
	SystemTimeAdjustment,					// 28       Y        Y
	SystemNotImplemented7,					// 29       Y        N
	SystemNotImplemented8,					// 30       Y        N
	SystemNotImplemented9,					// 31       Y        N
	SystemCrashDumpInformation,				// 32       Y        N
	SystemExceptionInformation,				// 33       Y        N
	SystemCrashDumpStateInformation,		// 34       Y        Y/N
	SystemKernelDebuggerInformation,		// 35       Y        N
	SystemContextSwitchInformation,			// 36       Y        N
	SystemRegistryQuotaInformation,			// 37       Y        Y
	SystemLoadAndCallImage,					// 38       N        Y
	SystemPrioritySeparation,				// 39       N        Y
	SystemNotImplemented10,					// 40       Y        N
	SystemNotImplemented11,					// 41       Y        N
	SystemInvalidInfoClass2,				// 42
	SystemInvalidInfoClass3,				// 43
	SystemTimeZoneInformation,				// 44       Y        N
	SystemLookasideInformation,				// 45       Y        N
	SystemSetTimeSlipEvent,					// 46       N        Y
	SystemCreateSession,					// 47       N        Y
	SystemDeleteSession,					// 48       N        Y
	SystemInvalidInfoClass4,				// 49
	SystemRangeStartInformation,			// 50       Y        N
	SystemVerifierInformation,				// 51       Y        Y
	SystemAddVerifier,						// 52       N        Y
	SystemSessionProcessesInformation		// 53       Y        N
} SYSTEM_INFORMATION_CLASS;

typedef struct _LSA_UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;

} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}CLIENT_ID, *PCLIENT_ID;

typedef enum _THREAD_STATE
{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown

} THREAD_STATE;

typedef enum _KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel
} KWAIT_REASON;

typedef struct _IO_COUNTERS_EX 
{
	LARGE_INTEGER ReadOperationCount;   //I/O读操作数目
	LARGE_INTEGER WriteOperationCount;  //I/O写操作数目
	LARGE_INTEGER OtherOperationCount;  //I/O其他操作数目
	LARGE_INTEGER ReadTransferCount;    //I/O读数据数目
	LARGE_INTEGER WriteTransferCount;   //I/O写数据数目
	LARGE_INTEGER OtherTransferCount;   //I/O其他操作数据数目
} IO_COUNTERS_EX, *PIO_COUNTERS_EX;

typedef struct _VM_COUNTERS
{
	ULONG PeakVirtualSize;              //虚拟存储峰值大小   
	ULONG VirtualSize;                  //虚拟存储大小   
	ULONG PageFaultCount;               //页故障数目   
	ULONG PeakWorkingSetSize;           //工作集峰值大小   
	ULONG WorkingSetSize;               //工作集大小   
	ULONG QuotaPeakPagedPoolUsage;      //分页池使用配额峰值   
	ULONG QuotaPagedPoolUsage;          //分页池使用配额   
	ULONG QuotaPeakNonPagedPoolUsage;   //非分页池使用配额峰值   
	ULONG QuotaNonPagedPoolUsage;       //非分页池使用配额   
	ULONG PagefileUsage;                //页文件使用情况   
	ULONG PeakPagefileUsage;            //页文件使用峰值   

} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	THREAD_STATE State;
	KWAIT_REASON WaitReason;

} SYSTEM_THREADS, *PSYSTEM_THREADS;

//进程数据结构
typedef struct _SYSTEM_PROCESSES
{
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS  VmCounters;
	IO_COUNTERS_EX IoCounters;	// Windows 2000 only
	SYSTEM_THREADS Threads[1];

} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

//模块数据结构
typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

//句柄数据结构
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG            ProcessId;
	UCHAR            ObjectTypeNumber;
	UCHAR            Flags;
	USHORT           Handle;
	PVOID            Object;
	ACCESS_MASK      GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATIONS {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATIONS, *PSYSTEM_HANDLE_INFORMATIONS;


typedef struct _SYSTEM_BASIC_INFORMATION
{
	BYTE Reserved1[24];
	PVOID Reserved2[4];
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS 
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_NAME_INFORMATION 
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

//定义函数指针
typedef NTSTATUS
(NTAPI *ZWQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef NTSTATUS(NTAPI *NTQUERYOBJECT)(
	_In_opt_   HANDLE Handle,
	_In_       OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_opt_  PVOID ObjectInformation,
	_In_       ULONG ObjectInformationLength,
	_Out_opt_  PULONG ReturnLength
	);

//ZWQUERYSYSTEMINFORMATION	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
//NTQUERYOBJECT	NtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");