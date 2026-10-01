/**
 * @file Types.h
 * @author Ky4meru (@ky4meru)
 * @brief NT structures, typedefs, and enumerations used across the framework.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_TYPES_H_
#define _MDK_TYPES_H_

#include <windows.h>

/**
 * @brief The PROC_MATCH structure contains the id of a process and its parent.
 */
typedef struct _MDK_PROC_MATCH
{
    DWORD Pid;
    DWORD ParentPid;
} MDK_PROC_MATCH, * MDK_PPROC_MATCH;

/**
 * @brief The CLIENT_ID structure contains identifiers of a process and a thread.
 */
typedef struct _MDK_CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MDK_CLIENT_ID, * MDK_PCLIENT_ID;

/**
 * @brief The USTRING structure defines a counted string used for generic strings.
 */
typedef struct _MDK_USTRING
{
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} MDK_USTRING, * MDK_PUSTRING;

/**
 * @brief The ANSI_STRING structure defines a counted string used for ANSI strings.
 */
typedef struct _MDK_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} MDK_STRING, * MDK_PSTRING, MDK_ANSI_STRING, * MDK_PANSI_STRING;

/**
 * @brief The UNICODE_STRING structure is used to define Unicode strings.
 */
typedef struct _MDK_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} MDK_UNICODE_STRING, * MDK_PUNICODE_STRING;

/**
 * @brief The OBJECT_ATTRIBUTES structure specifies attributes that can be applied to objects or object handles by routines that create objects and/or return handles to objects.
 */
typedef struct _MDK_OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    MDK_PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} MDK_OBJECT_ATTRIBUTES, * MDK_POBJECT_ATTRIBUTES;

/**
 * @brief A driver sets an IRP's I/O status block to indicate the final status of an I/O request, before calling IoCompleteRequest for the IRP.
 */
typedef struct _MDK_IO_STATUS_BLOCK
{
  union
  {
    NTSTATUS Status;
    PVOID    Pointer;
  };
  ULONG_PTR Information;
} MDK_IO_STATUS_BLOCK, * MDK_PIO_STATUS_BLOCK;

/**
 * @brief The LDR_INIT_ROUTINE function pointer type represents a DLL initialization routine (DllMain).
 */
typedef BOOLEAN(NTAPI* MDK_PLDR_INIT_ROUTINE)(_In_ PVOID DllHandle, _In_ ULONG Reason, _In_opt_ PVOID Context);

/**
 * @brief The LDR_SERVICE_TAG_RECORD structure represents a service tag entry in the loader's service tag list.
 */
typedef struct _MDK_LDR_SERVICE_TAG_RECORD
{
    struct _MDK_LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} MDK_LDR_SERVICE_TAG_RECORD, * MDK_PLDR_SERVICE_TAG_RECORD;

/**
 * @brief The LDRP_CSLIST structure represents a critical section-protected singly linked list used by the loader.
 */
typedef struct _MDK_LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} MDK_LDRP_CSLIST, * MDK_PLDRP_CSLIST;

/**
 * @brief The LDR_DDAG_STATE enumeration defines the loading states of a module in the loader's dependency graph.
 */
typedef enum _MDK_LDR_DDAG_STATE
{
    MdkLdrModulesMerged = -5,
    MdkLdrModulesInitError = -4,
    MdkLdrModulesSnapError = -3,
    MdkLdrModulesUnloaded = -2,
    MdkLdrModulesUnloading = -1,
    MdkLdrModulesPlaceHolder = 0,
    MdkLdrModulesMapping = 1,
    MdkLdrModulesMapped = 2,
    MdkLdrModulesWaitingForDependencies = 3,
    MdkLdrModulesSnapping = 4,
    MdkLdrModulesSnapped = 5,
    MdkLdrModulesCondensed = 6,
    MdkLdrModulesReadyToInit = 7,
    MdkLdrModulesInitializing = 8,
    MdkLdrModulesReadyToRun = 9
} MDK_LDR_DDAG_STATE;

/**
 * @brief The LDR_DDAG_NODE structure represents a node in the loader's directed dependency acyclic graph (DDAG).
 */
typedef struct _MDK_LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    MDK_PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        MDK_LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    MDK_LDRP_CSLIST IncomingDependencies;
    MDK_LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} MDK_LDR_DDAG_NODE, * MDK_PLDR_DDAG_NODE;

/**
 * @brief The RTL_BALANCED_NODE structure represents a node in an AVL or red-black tree used by the runtime library.
 */
typedef struct _MDK_RTL_BALANCED_NODE
{
    union
    {
        struct _MDK_RTL_BALANCED_NODE* Children[2];
        struct
        {
            struct _MDK_RTL_BALANCED_NODE* Left;
            struct _MDK_RTL_BALANCED_NODE* Right;
        };
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };


} MDK_RTL_BALANCED_NODE, * MDK_PRTL_BALANCED_NODE;

/**
 * @brief The LDR_DLL_LOAD_REASON enumeration defines the reason a DLL was loaded into the process.
 */
typedef enum _MDK_LDR_DLL_LOAD_REASON
{
    MdkLoadReasonStaticDependency,
    MdkLoadReasonStaticForwarderDependency,
    MdkLoadReasonDynamicForwarderDependency,
    MdkLoadReasonDelayloadDependency,
    MdkLoadReasonDynamicLoad,
    MdkLoadReasonAsImageLoad,
    MdkLoadReasonAsDataLoad,
    MdkLoadReasonEnclavePrimary,
    MdkLoadReasonEnclaveDependency,
    MdkLoadReasonUnknown = -1
} MDK_LDR_DLL_LOAD_REASON, * MDK_PLDR_DLL_LOAD_REASON;

/**
 * @brief The LDR_DATA_TABLE_ENTRY structure represents a module loaded for the process.
 */
typedef struct _MDK_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    MDK_PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    MDK_UNICODE_STRING FullDllName;
    MDK_UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock;
    MDK_PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    MDK_RTL_BALANCED_NODE BaseAddressIndexNode;
    MDK_RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    MDK_LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel;
} MDK_LDR_DATA_TABLE_ENTRY, * MDK_PLDR_DATA_TABLE_ENTRY;

/**
 * @brief The PEB_LDR_DATA structure contains information about the loaded modules for the process.
 */
typedef struct _MDK_PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} MDK_PEB_LDR_DATA, * MDK_PPEB_LDR_DATA;

/**
 * @brief The CURDIR structure contains information about the current directory of the running process.
 */
typedef struct _MDK_CURDIR
{
    MDK_UNICODE_STRING DosPath;
    HANDLE Handle;
} MDK_CURDIR, * MDK_PCURDIR;

/**
 * @brief The RTL_DRIVE_LETTER_CURDIR structure keeps a current directory for each drive (letter).
 */
typedef struct _MDK_RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    MDK_STRING DosPath;
} MDK_RTL_DRIVE_LETTER_CURDIR, * MDK_PRTL_DRIVE_LETTER_CURDIR;

/**
 * @brief The RTL_USER_PROCESS_PARAMETERS contains process parameter information.
 */
typedef struct _MDK_RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    MDK_CURDIR CurrentDirectory;
    MDK_UNICODE_STRING DllPath;
    MDK_UNICODE_STRING ImagePathName;
    MDK_UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    MDK_UNICODE_STRING WindowTitle;
    MDK_UNICODE_STRING DesktopInfo;
    MDK_UNICODE_STRING ShellInfo;
    MDK_UNICODE_STRING RuntimeData;
    MDK_RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
} MDK_RTL_USER_PROCESS_PARAMETERS, * MDK_PRTL_USER_PROCESS_PARAMETERS;

/**
 * @brief The Process Environment Block (PEB) structure contains process information.
 */
typedef struct _MDK_PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    MDK_PPEB_LDR_DATA Ldr;
    MDK_PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[60];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    MDK_UNICODE_STRING CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    SIZE_T MinimumStackCommit;
    PVOID FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG SpareTracingBits : 30;
        };
    };
} MDK_PEB, * MDK_PPEB;

/**
 * @brief The Thread Environment Block (TEB) structure describes the state of a thread.
 */
typedef struct _MDK_TEB
{
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    MDK_CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    MDK_PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    PVOID Reserved2[395];
    BYTE Reserved3[1952];
    PVOID TlsSlots[64];
    BYTE Reserved4[8];
    PVOID Reserved5[26];
    PVOID ReservedForOle;
    PVOID Reserved6[4];
    PVOID TlsExpansionSlots;
} MDK_TEB, * MDK_PTEB;

/**
 * @brief The KSYSTEM_TIME structure represents a 64-bit system time.
 */
typedef struct _MDK_KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} MDK_KSYSTEM_TIME, * MDK_PKSYSTEM_TIME;

/**
 * @brief The NT_PRODUCT_TYPE enum represents a native product type.
 */
typedef enum _MDK_NT_PRODUCT_TYPE
{
    MdkNtProductWinNt = 1,
    MdkNtProductLanManNt,
    MdkNtProductServer
} MDK_NT_PRODUCT_TYPE;

/**
 * @brief The ALTERNATIVE_ARCHITECTURE_TYPE enum represents an alternate architecture type.
 */
typedef enum _MDK_ALTERNATIVE_ARCHITECTURE_TYPE
{
    MdkStandardDesign,
    MdkNEC98x86,
    MdkEndAlternatives
} MDK_ALTERNATIVE_ARCHITECTURE_TYPE;

/**
 * @brief The KUSER_SHARED_DATA structure defines the layout of a data area that the kernel places at a pre-set address for sharing with user-mode software.
 */
typedef struct _MDK_KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    MDK_KSYSTEM_TIME InterruptTime;
    MDK_KSYSTEM_TIME SystemTime;
    MDK_KSYSTEM_TIME TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG AitSamplingValue;
    ULONG AppCompatFlag;
    ULONGLONG RNGSeedVersion;
    ULONG GlobalValidationRunlevel;
    LONG TimeZoneBiasStamp;
    ULONG NtBuildNumber;
    MDK_NT_PRODUCT_TYPE NtProductType;
    BOOLEAN ProductTypeIsValid;
    BOOLEAN Reserved0[1];
    USHORT NativeProcessorArchitecture;
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    BOOLEAN ProcessorFeatures[64];
    ULONG Reserved1;
    ULONG Reserved3;
    ULONG TimeSlip;
    MDK_ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG BootId;
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask;
    BOOLEAN KdDebuggerEnabled;
    union
    {
        UCHAR MitigationPolicies;
        struct
        {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT CyclesPerYield;
    ULONG ActiveConsoleId;
    ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    union
    {
        UCHAR VirtualizationFlags;
        struct
        {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR Reserved12[2];
    union
    {
        ULONG SharedDataFlags;
        struct
        {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    ULONG DataFlagsPad[1];
    ULONGLONG TestRetInstruction;
    LONGLONG QpcFrequency;
    ULONG SystemCall;
    ULONG Reserved2;
    ULONGLONG FullNumberOfPhysicalPages;
    ULONGLONG SystemCallPad[1];
    union
    {
        MDK_KSYSTEM_TIME TickCount;
        ULONG64 TickCountQuad;
        struct
        {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG Cookie;
    ULONG CookiePad[1];
    LONGLONG ConsoleSessionForegroundProcessId;
    ULONGLONG TimeUpdateLock;
    ULONGLONG BaselineSystemTimeQpc;
    ULONGLONG BaselineInterruptTimeQpc;
    ULONGLONG QpcSystemTimeIncrement;
    ULONGLONG QpcInterruptTimeIncrement;
    UCHAR QpcSystemTimeIncrementShift;
    UCHAR QpcInterruptTimeIncrementShift;
    USHORT UnparkedProcessorCount;
    ULONG EnclaveFeatureMask[4];
    ULONG TelemetryCoverageRound;
    USHORT UserModeGlobalLogger[16];
    ULONG ImageFileExecutionOptions;
    ULONG LangGenerationCount;
    ULONGLONG Reserved4;
    ULONGLONG InterruptTimeBias;
    ULONGLONG QpcBias;
    ULONG ActiveProcessorCount;
    UCHAR ActiveGroupCount;
    UCHAR Reserved9;
    union
    {
        USHORT QpcData;
        struct
        {
            UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };
    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION XState;
    MDK_KSYSTEM_TIME FeatureConfigurationChangeStamp;
    ULONG Spare;
    ULONG64 UserPointerAuthMask;
    XSTATE_CONFIGURATION XStateArm64;
    ULONG Reserved10[210];
} MDK_KUSER_SHARED_DATA, * MDK_PKUSER_SHARED_DATA;

/**
 * @brief The MDK_SPOOF_PARAMETERS structure defines the parameters passed to the Call Stack Spoofing stub.
 */
typedef struct _MDK_SPOOF_PARAMETERS
{
    LPVOID Fixup;
    LPVOID OriginalReturnAddress;
    LPVOID Rbx;
    LPVOID Rdi;
    LPVOID BaseThreadInitThunkStackSize;
    LPVOID BaseThreadInitThunkReturnAddress;
    LPVOID TrampolineStackSize;
    LPVOID RtlUserThreadStartStackSize;
    LPVOID RtlUserThreadStartReturnAddress;
    LPVOID Ssn;
    LPVOID Trampoline;
    LPVOID Rsi;
    LPVOID R12;
    LPVOID R13;
    LPVOID R14;
    LPVOID R15;
} MDK_SPOOF_PARAMETERS, * MDK_PSPOOF_PARAMETERS;

/**
 * @brief The MDK_UNWIND_CODE structure defines a single unwind code entry used in the x64 exception handling unwind procedure.
 */
typedef union _MDK_UNWIND_CODE
{
    struct
    {
        UCHAR CodeOffset;
        UCHAR UnwindOp : 4;
        UCHAR OpInfo : 4;
    };
    USHORT FrameOffset;
} MDK_UNWIND_CODE, * MDK_PUNWIND_CODE;

/**
 * @brief The UNWIND_CODE_OPS enumeration defines the error codes to handle ABI exceptions in x64.
 * 
 * For more information, see https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170.
 */
typedef enum _MDK_UNWIND_CODE_OPS
{
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} MDK_UNWIND_CODE_OPS;

/**
 * @brief The UNWIND_INFO structure records the effects a function has on the stack pointer and where the nonvolatile registers are saved on the stack.
 */
typedef struct _MDK_UNWIND_INFO
{
    UCHAR Version : 3;
    UCHAR Flags : 5;
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameRegister : 4;
    UCHAR FrameOffset : 4;
    MDK_UNWIND_CODE UnwindCode[1];
} MDK_UNWIND_INFO, * MDK_PUNWIND_INFO;

/**
 * @brief The PS_CREATE_STATE enum defines the initial state for a process creation.
 */
typedef enum _MDK_PS_CREATE_STATE
{
    MdkPsCreateInitialState,
    MdkPsCreateFailOnFileOpen,
    MdkPsCreateFailOnSectionCreate,
    MdkPsCreateFailExeFormat,
    MdkPsCreateFailMachineMismatch,
    MdkPsCreateFailExeName,
    MdkPsCreateSuccess,
    MdkPsCreateMaximumStates
} MDK_PS_CREATE_STATE;

/**
 * @brief The PS_CREATE_INFO structure is not documented.
 */
typedef struct _MDK_PS_CREATE_INFO
{
    SIZE_T Size;
    MDK_PS_CREATE_STATE State;
    union
    {
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;
        struct
        {
            HANDLE FileHandle;
        } FailSection;
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;
        struct
        {
            HANDLE IFEOKey;
        } ExeName;
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1;
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} MDK_PS_CREATE_INFO, * MDK_PPS_CREATE_INFO;

/**
 * @brief The PS_ATTRIBUTE structure is not documented.
 */
typedef struct _MDK_PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} MDK_PS_ATTRIBUTE, * MDK_PPS_ATTRIBUTE;

/**
 * @brief The PS_ATTRIBUTE_LIST structure is not documented.
 */
typedef struct _MDK_PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    MDK_PS_ATTRIBUTE Attributes[2];
} MDK_PS_ATTRIBUTE_LIST, * MDK_PPS_ATTRIBUTE_LIST;

/**
 * @brief The PROCESS_BASIC_INFORMATION structure contains basic information about a process.
 */
typedef struct _MDK_PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    MDK_PPEB PebBaseAddress;
    KAFFINITY AffinityMask;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} MDK_PROCESS_BASIC_INFORMATION, * MDK_PPROCESS_BASIC_INFORMATION;

/**
 * @brief The LDR_DATA_TABLE_ENTRY_FULL structure is not documented.
 */
typedef struct _MDK_LDR_DATA_TABLE_ENTRY_FULL
{
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    MDK_UNICODE_STRING FullDllName;
    MDK_UNICODE_STRING BaseDllName;
} MDK_LDR_DATA_TABLE_ENTRY_FULL, * MDK_PLDR_DATA_TABLE_ENTRY_FULL;

/**
 * @brief The SYSTEM_THREAD_INFORMATION structure contains information about a thread running on a system.
 */
typedef struct _MDK_SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    MDK_CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} MDK_SYSTEM_THREAD_INFORMATION, * MDK_PSYSTEM_THREAD_INFORMATION;

/**
 * @brief The SYSTEM_PROCESS_INFORMATION structure contains information about a process running on a system.
 */
typedef struct _MDK_SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;                     
    ULONG NumberOfThreads;                     
    ULONGLONG WorkingSetPrivateSize;           
    ULONG HardFaultCount;                      
    ULONG NumberOfThreadsHighWatermark;        
    ULONGLONG CycleTime;                       
    LARGE_INTEGER CreateTime;                  
    LARGE_INTEGER UserTime;              
    LARGE_INTEGER KernelTime;            
    MDK_UNICODE_STRING ImageName;        
    LONG BasePriority;                   
    HANDLE UniqueProcessId;              
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;                  
    ULONG SessionId;                    
    ULONG_PTR UniqueProcessKey;         
    SIZE_T PeakVirtualSize;             
    SIZE_T VirtualSize;                 
    ULONG PageFaultCount;               
    SIZE_T PeakWorkingSetSize;          
    SIZE_T WorkingSetSize;              
    SIZE_T QuotaPeakPagedPoolUsage;     
    SIZE_T QuotaPagedPoolUsage;          
    SIZE_T QuotaPeakNonPagedPoolUsage;   
    SIZE_T QuotaNonPagedPoolUsage;       
    SIZE_T PagefileUsage;                
    SIZE_T PeakPagefileUsage;            
    SIZE_T PrivatePageCount;             
    LARGE_INTEGER ReadOperationCount;    
    LARGE_INTEGER WriteOperationCount;   
    LARGE_INTEGER OtherOperationCount;   
    LARGE_INTEGER ReadTransferCount;     
    LARGE_INTEGER WriteTransferCount;    
    LARGE_INTEGER OtherTransferCount;    
    MDK_SYSTEM_THREAD_INFORMATION Threads[1];
} MDK_SYSTEM_PROCESS_INFORMATION, * MDK_PSYSTEM_PROCESS_INFORMATION;

/**
 * @brief The DBG_STATE enumeration defines the state of a debug object.
 */
typedef enum _MDK_DBG_STATE
{
    MdkDbgIdle,
    MdkDbgReplyPending,
    MdkDbgCreateThreadStateChange,
    MdkDbgCreateProcessStateChange,
    MdkDbgExitThreadStateChange,
    MdkDbgExitProcessStateChange,
    MdkDbgExceptionStateChange,
    MdkDbgBreakpointStateChange,
    MdkDbgSingleStepStateChange,
    MdkDbgLoadDllStateChange,
    MdkDbgUnloadDllStateChange
} MDK_DBG_STATE, * MDK_PDBG_STATE;

/**
 * @brief The DBGKM_EXCEPTION structure contains exception information for a debug event.
 */
typedef struct _MDK_DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} MDK_DBGKM_EXCEPTION, * MDK_PDBGKM_EXCEPTION;

/**
 * @brief The DBGKM_CREATE_THREAD structure contains information about a newly created thread.
 */
typedef struct _MDK_DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} MDK_DBGKM_CREATE_THREAD, * MDK_PDBGKM_CREATE_THREAD;

/**
 * @brief The DBGUI_CREATE_THREAD structure contains UI-level information about a newly created thread.
 */
typedef struct _MDK_DBGUI_CREATE_THREAD
{
    HANDLE HandleToThread;
    MDK_DBGKM_CREATE_THREAD NewThread;
} MDK_DBGUI_CREATE_THREAD, * MDK_PDBGUI_CREATE_THREAD;

/**
 * @brief The DBGKM_CREATE_PROCESS structure contains information about a newly created process.
 */
typedef struct _MDK_DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    MDK_DBGKM_CREATE_THREAD InitialThread;
} MDK_DBGKM_CREATE_PROCESS, * MDK_PDBGKM_CREATE_PROCESS;

/**
 * @brief The DBGUI_CREATE_PROCESS structure contains UI-level information about a newly created process.
 */
typedef struct _MDK_DBGUI_CREATE_PROCESS
{
    HANDLE HandleToProcess;
    HANDLE HandleToThread;
    MDK_DBGKM_CREATE_PROCESS NewProcess;
} MDK_DBGUI_CREATE_PROCESS, * MDK_PDBGUI_CREATE_PROCESS;

/**
 * @brief The DBGKM_EXIT_THREAD structure contains the exit status of a thread.
 */
typedef struct _MDK_DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} MDK_DBGKM_EXIT_THREAD, * MDK_PDBGKM_EXIT_THREAD;

/**
 * @brief The DBGKM_EXIT_PROCESS structure contains the exit status of a process.
 */
typedef struct _MDK_DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} MDK_DBGKM_EXIT_PROCESS, * MDK_PDBGKM_EXIT_PROCESS;

/**
 * @brief The DBGKM_LOAD_DLL structure contains information about a loaded DLL.
 */
typedef struct _MDK_DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} MDK_DBGKM_LOAD_DLL, * MDK_PDBGKM_LOAD_DLL;

/**
 * @brief The DBGKM_UNLOAD_DLL structure contains the base address of an unloaded DLL.
 */
typedef struct _MDK_DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
} MDK_DBGKM_UNLOAD_DLL, * MDK_PDBGKM_UNLOAD_DLL;

/**
 * @brief The DBGUI_WAIT_STATE_CHANGE structure contains information about a debug state change.
 */
typedef struct _MDK_DBGUI_WAIT_STATE_CHANGE
{
    MDK_DBG_STATE NewState;
    MDK_CLIENT_ID AppClientId;
    union
    {
        MDK_DBGKM_EXCEPTION Exception;
        MDK_DBGUI_CREATE_THREAD CreateThread;
        MDK_DBGUI_CREATE_PROCESS CreateProcessInfo;
        MDK_DBGKM_EXIT_THREAD ExitThread;
        MDK_DBGKM_EXIT_PROCESS ExitProcess;
        MDK_DBGKM_LOAD_DLL LoadDll;
        MDK_DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} MDK_DBGUI_WAIT_STATE_CHANGE, * MDK_PDBGUI_WAIT_STATE_CHANGE;

/**
 * @brief The SHELLCODE_LOADING_METHOD enumeration defines the available methods to load shellcode into memory.
 */
typedef enum _MDK_SHELLCODE_LOADING_METHOD
{
    MdkBasicShellcodeLoad,
    MdkModuleStompingLoad,
    MdkDripLoad
} MDK_SHELLCODE_LOADING_METHOD, * MDK_PSHELLCODE_LOADING_METHOD;

/**
 * @brief The INJECTION_TECHNIQUE enumeration defines the available code injection techniques.
 */
typedef enum _MDK_INJECTION_TECHNIQUE
{
    MdkTpAllocLocalInjection,
    MdkThreadlessViaHwbpLocalInjection,
    MdkEarlyCryoBirdRemoteInjection,
    MdkPoolPartyViaTpDirectRemoteInjection,
    MdkEntryPointHijackingRemoteInjection
} MDK_INJECTION_TECHNIQUE, * MDK_PINJECTION_TECHNIQUE;

/**
 * @brief The ALLOCATION_METHOD enumeration defines the available memory allocation strategies.
 */
typedef enum _MDK_ALLOCATOR
{
    MdkBasicLoadAllocation,
    MdkModuleStompingAllocation,
    MdkDripLoadAllocation
} MDK_ALLOCATOR, * MDK_PALLOCATOR;

/**
 * @brief The KERNELCALLBACKTABLE structure mirrors the KernelCallbackTable layout referenced by the PEB, containing user-mode callback function pointers invoked by win32k.
 */
typedef struct _MDK_KERNELCALLBACKTABLE {
    ULONG_PTR __fnCOPYDATA;
    ULONG_PTR __fnCOPYGLOBALDATA;
    ULONG_PTR __fnDWORD;
    ULONG_PTR __fnNCDESTROY;
    ULONG_PTR __fnDWORDOPTINLPMSG;
    ULONG_PTR __fnINOUTDRAG;
    ULONG_PTR __fnGETTEXTLENGTHS;
    ULONG_PTR __fnINCNTOUTSTRING;
    ULONG_PTR __fnPOUTLPINT;
    ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
    ULONG_PTR __fnINLPCREATESTRUCT;
    ULONG_PTR __fnINLPDELETEITEMSTRUCT;
    ULONG_PTR __fnINLPDRAWITEMSTRUCT;
    ULONG_PTR __fnPOPTINLPUINT;
    ULONG_PTR __fnPOPTINLPUINT2;
    ULONG_PTR __fnINLPMDICREATESTRUCT;
    ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
    ULONG_PTR __fnINLPWINDOWPOS;
    ULONG_PTR __fnINOUTLPPOINT5;
    ULONG_PTR __fnINOUTLPSCROLLINFO;
    ULONG_PTR __fnINOUTLPRECT;
    ULONG_PTR __fnINOUTNCCALCSIZE;
    ULONG_PTR __fnINOUTLPPOINT5_;
    ULONG_PTR __fnINPAINTCLIPBRD;
    ULONG_PTR __fnINSIZECLIPBRD;
    ULONG_PTR __fnINDESTROYCLIPBRD;
    ULONG_PTR __fnINSTRING;
    ULONG_PTR __fnINSTRINGNULL;
    ULONG_PTR __fnINDEVICECHANGE;
    ULONG_PTR __fnPOWERBROADCAST;
    ULONG_PTR __fnINLPUAHDRAWMENU;
    ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
    ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
    ULONG_PTR __fnOUTDWORDINDWORD;
    ULONG_PTR __fnOUTLPRECT;
    ULONG_PTR __fnOUTSTRING;
    ULONG_PTR __fnPOPTINLPUINT3;
    ULONG_PTR __fnPOUTLPINT2;
    ULONG_PTR __fnSENTDDEMSG;
    ULONG_PTR __fnINOUTSTYLECHANGE;
    ULONG_PTR __fnHkINDWORD;
    ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
    ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
    ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
    ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMSG;
    ULONG_PTR __fnHkINLPRECT;
    ULONG_PTR __fnHkOPTINLPEVENTMSG;
    ULONG_PTR __xxxClientCallDelegateThread;
    ULONG_PTR __ClientCallDummyCallback;
    ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
    ULONG_PTR __fnOUTLPCOMBOBOXINFO;
    ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
    ULONG_PTR __xxxClientCallDevCallbackCapture;
    ULONG_PTR __xxxClientCallDitThread;
    ULONG_PTR __xxxClientEnableMMCSS;
    ULONG_PTR __xxxClientUpdateDpi;
    ULONG_PTR __xxxClientExpandStringW;
    ULONG_PTR __ClientCopyDDEIn1;
    ULONG_PTR __ClientCopyDDEIn2;
    ULONG_PTR __ClientCopyDDEOut1;
    ULONG_PTR __ClientCopyDDEOut2;
    ULONG_PTR __ClientCopyImage;
    ULONG_PTR __ClientEventCallback;
    ULONG_PTR __ClientFindMnemChar;
    ULONG_PTR __ClientFreeDDEHandle;
    ULONG_PTR __ClientFreeLibrary;
    ULONG_PTR __ClientGetCharsetInfo;
    ULONG_PTR __ClientGetDDEFlags;
    ULONG_PTR __ClientGetDDEHookData;
    ULONG_PTR __ClientGetListboxString;
    ULONG_PTR __ClientGetMessageMPH;
    ULONG_PTR __ClientLoadImage;
    ULONG_PTR __ClientLoadLibrary;
    ULONG_PTR __ClientLoadMenu;
    ULONG_PTR __ClientLoadLocalT1Fonts;
    ULONG_PTR __ClientPSMTextOut;
    ULONG_PTR __ClientLpkDrawTextEx;
    ULONG_PTR __ClientExtTextOutW;
    ULONG_PTR __ClientGetTextExtentPointW;
    ULONG_PTR __ClientCharToWchar;
    ULONG_PTR __ClientAddFontResourceW;
    ULONG_PTR __ClientThreadSetup;
    ULONG_PTR __ClientDeliverUserApc;
    ULONG_PTR __ClientNoMemoryPopup;
    ULONG_PTR __ClientMonitorEnumProc;
    ULONG_PTR __ClientCallWinEventProc;
    ULONG_PTR __ClientWaitMessageExMPH;
    ULONG_PTR __ClientWOWGetProcModule;
    ULONG_PTR __ClientWOWTask16SchedNotify;
    ULONG_PTR __ClientImmLoadLayout;
    ULONG_PTR __ClientImmProcessKey;
    ULONG_PTR __fnIMECONTROL;
    ULONG_PTR __fnINWPARAMDBCSCHAR;
    ULONG_PTR __fnGETTEXTLENGTHS2;
    ULONG_PTR __fnINLPKDRAWSWITCHWND;
    ULONG_PTR __ClientLoadStringW;
    ULONG_PTR __ClientLoadOLE;
    ULONG_PTR __ClientRegisterDragDrop;
    ULONG_PTR __ClientRevokeDragDrop;
    ULONG_PTR __fnINOUTMENUGETOBJECT;
    ULONG_PTR __ClientPrinterThunk;
    ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
    ULONG_PTR __fnOUTLPSCROLLBARINFO;
    ULONG_PTR __fnINLPUAHDRAWMENU2;
    ULONG_PTR __fnINLPUAHDRAWMENUITEM;
    ULONG_PTR __fnINLPUAHDRAWMENU3;
    ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
    ULONG_PTR __fnINLPUAHDRAWMENU4;
    ULONG_PTR __fnOUTLPTITLEBARINFOEX;
    ULONG_PTR __fnTOUCH;
    ULONG_PTR __fnGESTURE;
    ULONG_PTR __fnPOPTINLPUINT4;
    ULONG_PTR __fnPOPTINLPUINT5;
    ULONG_PTR __xxxClientCallDefaultInputHandler;
    ULONG_PTR __fnEMPTY;
    ULONG_PTR __ClientRimDevCallback;
    ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
    ULONG_PTR __ClientCallLocalMouseHooks;
    ULONG_PTR __xxxClientBroadcastThemeChange;
    ULONG_PTR __xxxClientCallDevCallbackSimple;
    ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
    ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
    ULONG_PTR __fnGETWINDOWDATA;
    ULONG_PTR __fnINOUTSTYLECHANGE2;
    ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
} MDK_KERNELCALLBACKTABLE, *MDK_PKERNELCALLBACKTABLE;

/**
 * @brief The PROCESS_HANDLE_TABLE_ENTRY_INFO structure contains information about a single handle in a process handle table.
 */
typedef struct _MDK_PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} MDK_PROCESS_HANDLE_TABLE_ENTRY_INFO, * MDK_PPROCESS_HANDLE_TABLE_ENTRY_INFO;

/**
 * @brief The PROCESS_HANDLE_SNAPSHOT_INFORMATION structure contains a snapshot of all handles in a process.
 */
typedef struct _MDK_PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    _Field_size_(NumberOfHandles) MDK_PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} MDK_PROCESS_HANDLE_SNAPSHOT_INFORMATION, * MDK_PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

/**
 * @brief The PUBLIC_OBJECT_TYPE_INFORMATION structure contains public type information about a kernel object.
 */
typedef struct _MDK_PUBLIC_OBJECT_TYPE_INFORMATION
{
    MDK_UNICODE_STRING TypeName;
    ULONG Reserved[22];
} MDK_PUBLIC_OBJECT_TYPE_INFORMATION, * MDK_PPUBLIC_OBJECT_TYPE_INFORMATION;

/**
 * @brief The TP_TASK_CALLBACKS structure holds the execute and unposted callback pointers for a thread pool task.
 */
typedef struct _MDK_TP_TASK_CALLBACKS
{
    LPVOID ExecuteCallback;
    LPVOID Unposted;
} MDK_TP_TASK_CALLBACKS, * MDK_PTP_TASK_CALLBACKS;

/**
 * @brief The TP_TASK structure represents a thread pool task with its callbacks and scheduling metadata.
 */
typedef struct _MDK_TP_TASK
{
    MDK_PTP_TASK_CALLBACKS Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    CHAR Padding_242[3];
    LIST_ENTRY ListEntry;
} MDK_TP_TASK, * MDK_PTP_TASK;

/**
 * @brief The TP_DIRECT structure represents a direct thread pool work item used for I/O completion callbacks.
 */
typedef struct _MDK_TP_DIRECT
{
    MDK_TP_TASK Task;
    UINT64 Lock;
    LIST_ENTRY IoCompletionInformationList;
    LPVOID Callback;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    CHAR __PADDING__[3];
} MDK_TP_DIRECT, * MDK_PTP_DIRECT;

/**
 * @brief The CFG_CALL_TARGET_LIST_INFORMATION structure describes a list of Control Flow Guard (CFG) valid call targets.
 */
typedef struct _MDK_CFG_CALL_TARGET_LIST_INFORMATION
{
    ULONG NumberOfEntries;
    ULONG Reserved;
    PULONG NumberOfEntriesProcessed;
    PCFG_CALL_TARGET_INFO CallTargetInfo;
    PVOID Section;
    ULONGLONG FileOffset;
} MDK_CFG_CALL_TARGET_LIST_INFORMATION, * MDK_PCFG_CALL_TARGET_LIST_INFORMATION;

/**
 * @brief The MEMORY_RANGE_ENTRY structure defines a virtual address range for memory management operations.
 */
typedef struct _MDK_MEMORY_RANGE_ENTRY
{
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} MDK_MEMORY_RANGE_ENTRY, * MDK_PMEMORY_RANGE_ENTRY;

/**
 * @brief The MEM_EXTENDED_PARAMETER structure specifies extended parameters for memory allocation and mapping operations.
 */
typedef struct _MDK_MEM_EXTENDED_PARAMETER
{
    struct
    {
        UINT64 Type : 8;
        UINT64 Reserved : 56;
    } DUMMYSTRUCTNAME;
    union
    {
        UINT64 ULong64;
        PVOID  Pointer;
        SIZE_T Size;
        HANDLE Handle;
        UINT32 ULong;
    } DUMMYUNIONNAME;
} MDK_MEM_EXTENDED_PARAMETER, * MDK_PMEM_EXTENDED_PARAMETER;

/**
 * @brief The JOBOBJECT_WAKE_FILTER structure specifies the edge transition filters for waking a frozen job object.
 */
typedef struct _MDK_JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;
    ULONG LowEdgeFilter;
} MDK_JOBOBJECT_WAKE_FILTER, * MDK_PJOBOBJECT_WAKE_FILTER;

/**
 * @brief The JOBOBJECT_FREEZE_INFORMATION structure contains parameters to freeze or swap processes within a job object.
 */
typedef struct _MDK_JOBOBJECT_FREEZE_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG FreezeOperation : 1;
            ULONG FilterOperation : 1;
            ULONG SwapOperation : 1;
            ULONG Reserved : 29;
        };
    };
    BOOLEAN Freeze;
    BOOLEAN Swap;
    UCHAR Reserved0[2];
    MDK_JOBOBJECT_WAKE_FILTER WakeFilter;
} MDK_JOBOBJECT_FREEZE_INFORMATION, * MDK_PJOBOBJECT_FREEZE_INFORMATION;

#endif // _MDK_TYPES_H_
