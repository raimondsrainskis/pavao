//! # errors
//!
//! this module exposes all the protocol errors

/**
 * MIT License
 *
 * pavao - Copyright (C) 2021 Christian Visintin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
// deps
use thiserror::Error;

/// ## Error
///
/// Describes an error type for
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Command error: `{0}`")]
    CommandError(ErrorCode),
    #[error("Invalid message syntax")]
    InvalidSyntax,
    #[error("Invalid client builder options due to missing argument: {0}")]
    MissingArg(String),
    #[error("Unknown error code")]
    UnknownErrorCode,
    #[error("Unknown command")]
    UnknownCommand,
}

/// ## ErrorCode
///
/// Describes an error returned in state. For SMB2 the values are listed here:
/// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55>
#[derive(Clone, Copy, Debug, Error, FromPrimitive, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    #[error("The operation completed successfully")]
    Success = 0x00000000,
    #[error("The operation was aborted")]
    Aborted = 0xffffffff,
    #[error("The operation that was requested is pending completion")]
    Pending = 0x00000103,
    #[error("Bad SMB fid")]
    SmbBadFid = 0x00060001,
    #[error("No more files were found which match the file specification")]
    NoMoreFiles = 0x80000006,
    #[error("The requested operation was unsuccessful")]
    Unsuccessful = 0xC0000001,
    #[error("The requested operation is not implemented")]
    NotImplemented = 0xC0000002,
    #[error(
        "The specified information class is not a valid information class for the specified object"
    )]
    InvalidInfoClass = 0xC0000003,
    #[error("The specified information record length does not match the length that is required for the specified information class")]
    InfoLengthMismatch = 0xC0000004,
    #[error("Memory access violation (or segmentation fault)")]
    AccessViolation = 0xC0000005,
    #[error("Memory page error")]
    InPageError = 0xC0000006,
    #[error("The page file quota for the process has been exhausted")]
    PagefileQuota = 0xC0000007,
    #[error("An invalid HANDLE was specified")]
    InvalidHandle = 0xC0000008,
    #[error("An invalid initial stack was specified in a call to NtCreateThread")]
    BadInitialStack = 0xC0000009,
    #[error("An invalid initial start address was specified in a call to NtCreateThread")]
    BadInitialPc = 0xC000000A,
    #[error("An invalid client ID was specified")]
    InvalidCid = 0xC000000B,
    #[error("An attempt was made to cancel or set a timer that has an associated APC and the specified thread is not the thread that originally set the timer with an associated APC routine")]
    TimerNotCanceled = 0xC000000C,
    #[error("An invalid parameter was passed to a service or function")]
    InvalidParameter = 0xC000000D,
    #[error("A device that does not exist was specified")]
    NoSuchDevice = 0xC000000E,
    #[error("No such file")]
    NoSuchFile = 0xC000000F,
    #[error("The specified request is not a valid operation for the target device")]
    InvalidDeviceRequest = 0xC0000010,
    #[error("The end-of-file marker has been reached. There is no valid data in the file beyond this marker")]
    EndOfFile = 0xC0000011,
    #[error("The wrong volume is in the drive")]
    WrongVolume = 0xC0000012,
    #[error("There is no disk in the drive")]
    NoMediaInDevice = 0xC0000013,
    #[error("The disk in drive is not formatted properly")]
    UnrecognizedMedia = 0xC0000014,
    #[error("The specified sector does not exist")]
    NonexistentSector = 0xC0000015,
    #[error("The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete")]
    MoreProcessingRequired = 0xC0000016,
    #[error("Not enough virtual memory or paging file quota is available to complete the specified operation.")]
    NoMemory = 0xC0000017,
    #[error("The specified address range conflicts with the address space")]
    ConflictingAddresses = 0xC0000018,
    #[error("The address range to unmap is not a mapped view")]
    NotMappedView = 0xC0000019,
    #[error("The virtual memory cannot be freed")]
    UnableToFreeVm = 0xC000001A,
    #[error("The specified section cannot be deleted")]
    UnableToDeleteSection = 0xC000001B,
    #[error("An invalid system service was specified in a system service call")]
    InvalidSystemService = 0xC000001C,
    #[error("Illegal Instruction An attempt was made to execute an illegal instruction")]
    IllegalInstruction = 0xC000001D,
    #[error("An attempt was made to execute an invalid lock sequence")]
    InvalidLockSequence = 0xC000001E,
    #[error("An attempt was made to create a view for a section that is bigger than the section")]
    InvalidViewSize = 0xC000001F,
    #[error("The attributes of the specified mapping file for a section of memory cannot be read")]
    InvalidFileForSection = 0xC0000020,
    #[error("The specified address range is already committed")]
    AlreadyCommitted = 0xC0000021,
    #[error(
        "A process has requested access to an object but has not been granted those access rights"
    )]
    AccessDenied = 0xC0000022,
    #[error("The buffer is too small to contain the entry. No information has been written to the buffer")]
    BufferTooSmall = 0xC0000023,
    #[error("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request")]
    ObjectTypeMismatch = 0xC0000024,
    #[error("Cannot Continue Windows cannot continue from this exception")]
    NoncontinuableException = 0xC0000025,
    #[error("An invalid exception disposition was returned by an exception handler")]
    InvalidDisposition = 0xC0000026,
    #[error("Unwind exception code")]
    Unwind = 0xC0000027,
    #[error("An invalid or unaligned stack was encountered during an unwind operation")]
    BadStack = 0xC0000028,
    #[error("An invalid unwind target was encountered during an unwind operation")]
    InvalidUnwindTarget = 0xC0000029,
    #[error("An attempt was made to unlock a page of memory that was not locked")]
    NotLocked = 0xC000002A,
    #[error("A device parity error on an I/O operation")]
    ParityError = 0xC000002B,
    #[error("An attempt was made to decommit uncommitted virtual memory")]
    UnableToDecommitVm = 0xC000002C,
    #[error("An attempt was made to change the attributes on memory that has not been committed")]
    NotCommitted = 0xC000002D,
    #[error("Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort")]
    InvalidPortAttributes = 0xC000002E,
    #[error("The length of the message that was passed to NtRequestPort or NtRequestWaitReplyPort is longer than the maximum message that is allowed by the port")]
    PortMessageTooLong = 0xC000002F,
    #[error("An invalid combination of parameters was specified")]
    InvalidParameterMix = 0xC0000030,
    #[error("An attempt was made to lower a quota limit below the current usage")]
    InvalidQuotaLower = 0xC0000031,
    #[error("The file system structure on the disk is corrupt and unusable")]
    DiskCorruptError = 0xC0000032,
    #[error("The object name is invalid")]
    ObjectNameInvalid = 0xC0000033,
    #[error("The object name is not found")]
    ObjectNameNotFound = 0xC0000034,
    #[error("The object name already exists")]
    ObjectNameCollision = 0xC0000035,
    #[error("Handle not waitable")]
    HandleNotWaitable = 0xC0000036,
    #[error("An attempt was made to send a message to a disconnected communication port")]
    PortDisconnected = 0xC0000037,
    #[error(
        "An attempt was made to attach to a device that was already attached to another device"
    )]
    DeviceAlreadyAttached = 0xC0000038,
    #[error("The object path component was not a directory object")]
    ObjectPathInvalid = 0xC0000039,
    #[error("Path Not Found")]
    ObjectPathNotFound = 0xC000003A,
    #[error("The object path component was not a directory object.")]
    ObjectPathSyntaxBad = 0xC000003B,
    #[error("A data overrun error occurred")]
    DataOverrun = 0xC000003C,
    #[error("A data late error occurred")]
    DataLateError = 0xC000003D,
    #[error("An error occurred in reading or writing data")]
    DataError = 0xC000003E,
    #[error("A cyclic redundancy check (CRC) checksum error occurred")]
    CrcError = 0xC000003F,
    #[error("The specified section is too big to map the file")]
    SectionTooBig = 0xC0000040,
    #[error("The NtConnectPort request is refused")]
    PortConnectionRefused = 0xC0000041,
    #[error("The type of port handle is invalid for the operation that is requested")]
    InvalidPortHandle = 0xC0000042,
    #[error("A file cannot be opened because the share access flags are incompatible")]
    SharingViolation = 0xC0000043,
    #[error("Insufficient quota exists to complete the operation")]
    QuotaExceeded = 0xC0000044,
    #[error("The specified page protection was not valid")]
    InvalidPageProtection = 0xC0000045,
    #[error("An attempt to release a mutant object was made by a thread that was not the owner of the mutant object")]
    MutantNotOwned = 0xC0000046,
    #[error("An attempt was made to release a semaphore such that its maximum count would have been exceeded")]
    SemaphoreLimitExceeded = 0xC0000047,
    #[error("An attempt was made to set the DebugPort or ExceptionPort of a process, but a port already exists in the process, or an attempt was made to set the CompletionPort of a file but a port was already set in the file, or an attempt was made to set the associated completion port of an ALPC port but it is already set")]
    PortAlreadySet = 0xC0000048,
    #[error(
        "An attempt was made to query image information on a section that does not map an image"
    )]
    SectionNotImage = 0xC0000049,
    #[error("An attempt was made to suspend a thread whose suspend count was at its maximum")]
    SuspendCountExceeded = 0xC000004A,
    #[error("An attempt was made to suspend a thread that has begun termination")]
    ThreadIsTerminating = 0xC000004B,
    #[error("An attempt was made to set the working set limit to an invalid value")]
    BadWorkingSetLimit = 0xC000004C,
    #[error("A section was created to map a file that is not compatible with an already existing section that maps the same file")]
    IncompatibleFileMap = 0xC000004D,
    #[error("A view to a section specifies a protection that is incompatible with the protection of the initial view")]
    SectionProtection = 0xC000004E,
    #[error("An operation involving EAs failed because the file system does not support EAs")]
    EasNotSupported = 0xC000004F,
    #[error("An EA operation failed because the EA set is too large")]
    EaTooLarge = 0xC0000050,
    #[error("An EA operation failed because the name or EA index is invalid")]
    NonexistentEaEntry = 0xC0000051,
    #[error("The file for which EAs were requested has no EAs")]
    NoEasOnFile = 0xC0000052,
    #[error("The EA is corrupt and cannot be read")]
    EaCorruptError = 0xC0000053,
    #[error("A requested read/write cannot be granted due to a conflicting file lock")]
    FileLockConflict = 0xC0000054,
    #[error("A requested file lock cannot be granted due to other existing locks")]
    LockNotGranted = 0xC0000055,
    #[error("A non-close operation has been requested of a file object that has a delete pending")]
    DeletePending = 0xC0000056,
    #[error("An attempt was made to set the control attribute on a file. This attribute is not supported in the destination file system")]
    CtlFileNotSupported = 0xC0000057,
    #[error("Indicates a revision number that was encountered or specified is not one that is known by the service. It might be a more recent revision than the service is aware of")]
    UnknownRevision = 0xC0000058,
    #[error("two revision levels are incompatible")]
    RevisionMismatch = 0xC0000059,
    #[error("Indicates a particular security ID cannot be assigned as the owner of an object")]
    InvalidOwner = 0xC000005A,
    #[error(
        "Indicates a particular security ID cannot be assigned as the primary group of an object"
    )]
    InvalidPrimaryGroup = 0xC000005B,
    #[error("An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client")]
    NoImpersonationToken = 0xC000005C,
    #[error("A mandatory group cannot be disabled")]
    CantDisableMandatory = 0xC000005D,
    #[error("No logon servers are currently available to service the logon request")]
    NoLogonServers = 0xC000005E,
    #[error("A specified logon session does not exist. It might already have been terminated")]
    NoSuchLogonSession = 0xC000005F,
    #[error("A specified privilege does not exist")]
    NoSuchPrivilege = 0xC0000060,
    #[error("A required privilege is not held by the client")]
    PrivilegeNotHeld = 0xC0000061,
    #[error("The name provided is not a properly formed account name")]
    InvalidAccountName = 0xC0000062,
    #[error("The specified account already exists")]
    UserExists = 0xC0000063,
    #[error("The specified account does not exist")]
    NoSuchUser = 0xC0000064,
    #[error("The specified group already exists")]
    GroupExists = 0xC0000065,
    #[error("The specified group does not exist")]
    NoSuchGroup = 0xC0000066,
    #[error("The specified user account is already in the specified group account. Also used to indicate a group cannot be deleted because it contains a member")]
    MemberInGroup = 0xC0000067,
    #[error("The specified user account is not a member of the specified group account")]
    MemberNotInGroup = 0xC0000068,
    #[error("Indicates the requested operation would disable or delete the last remaining administration account. This is not allowed to prevent creating a situation in which the system cannot be administrated")]
    LastAdmin = 0xC0000069,
    #[error("When trying to update a password, this return status indicates that the value provided as the current password is not correct")]
    WrongPassword = 0xC000006A,
    #[error("When trying to update a password, this return status indicates that the value provided for the new password contains values that are not allowed in passwords")]
    IllFormedPassword = 0xC000006B,
    #[error("When trying to update a password, this status indicates that some password update rule has been violated. For example, the password might not meet length criteria")]
    PasswordRestriction = 0xC000006C,
    #[error("The attempted logon is invalid. This is either due to a bad username or authentication information")]
    LogonFailure = 0xC000006D,
    #[error("Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication")]
    AccountRestriction = 0xC000006E,
    #[error("The user account has time restrictions and cannot be logged onto at this time")]
    InvalidLogonHours = 0xC000006F,
    #[error("The user account is restricted so that it cannot be used to log on from the source workstation")]
    InvalidWorkstation = 0xC0000070,
    #[error("The user account password has expired")]
    PasswordExpired = 0xC0000071,
    #[error("The referenced account is currently disabled and cannot be logged on to")]
    AccountDisabled = 0xC0000072,
    #[error("None of the information to be translated has been translated")]
    NoneMapped = 0xC0000073,
    #[error("The number of LUIDs requested cannot be allocated with a single allocation")]
    TooManyLuidsRequested = 0xC0000074,
    #[error("There are no more LUIDs to allocate")]
    LuidsExhausted = 0xC0000075,
    #[error("The sub-authority value is invalid for the particular use")]
    InvalidSubAuthority = 0xC0000076,
    #[error("The ACL structure is not valid")]
    InvalidAcl = 0xC0000077,
    #[error("The SID structure is not valid")]
    InvalidSid = 0xC0000078,
    #[error("The SECURITY_DESCRIPTOR structure is not valid")]
    InvalidSecurityDescr = 0xC0000079,
    #[error("The specified procedure address cannot be found in the DLL")]
    ProcedureNotFound = 0xC000007A,
    #[error("Bad image")]
    InvalidImageFormat = 0xC000007B,
    #[error("An attempt was made to reference a token that does not exist. This is typically done by referencing the token that is associated with a thread when the thread is not impersonating a client")]
    NoToken = 0xC000007C,
    #[error("An attempt to build either an inherited ACL or ACE was not successful")]
    BadInheritanceAcl = 0xC000007D,
    #[error("The range specified in NtUnlockFile was not locked")]
    RangeNotLocked = 0xC000007E,
    #[error("An operation failed because the disk was full.")]
    DiskFull = 0xC000007F,
    #[error("The GUID allocation server is disabled at the moment")]
    ServerDisabled = 0xC0000080,
    #[error("The GUID allocation server is enabled at the moment")]
    ServerNotDisabled = 0xC0000081,
    #[error("Too many GUIDs were requested from the allocation server at once")]
    TooManyGuidsRequested = 0xC0000082,
    #[error("The GUIDs could not be allocated because the Authority Agent was exhausted")]
    GuidsExhausted = 0xC0000083,
    #[error("The value provided was an invalid value for an identifier authority")]
    InvalidIdAuthority = 0xC0000084,
    #[error("No more authority agent values are available for the particular identifier authority value")]
    AgentsExhausted = 0xC0000085,
    #[error("An invalid volume label has been specified")]
    InvalidVolumeLabel = 0xC0000086,
    #[error("A mapped section could not be extended")]
    SectionNotExtended = 0xC0000087,
    #[error("Specified section to flush does not map a data file")]
    NotMappedData = 0xC0000088,
    #[error("Indicates the specified image file did not contain a resource section")]
    ResourceDataNotFound = 0xC0000089,
    #[error("Indicates the specified resource type cannot be found in the image file")]
    ResourceTypeNotFound = 0xC000008A,
    #[error("Indicates the specified resource name cannot be found in the image file")]
    ResourceNameNotFound = 0xC000008B,
    #[error("Array bounds exceeded")]
    ArrayBoundsExceeded = 0xC000008C,
    #[error("Floating-point denormal operand")]
    FloatDenormalOperand = 0xC000008D,
    #[error("Floating-point division by zero")]
    FloatDivideByZero = 0xC000008E,
    #[error("Floating-point inexact result")]
    FloatInexactResult = 0xC000008F,
    #[error("Floating-point invalid operation")]
    FloatInvalidOperation = 0xC0000090,
    #[error("Floating-point overflow")]
    FloatOverflow = 0xC0000091,
    #[error("Floating-point stack check")]
    FloatStackCheck = 0xC0000092,
    #[error("Floating-point underflow")]
    FloatUnderflow = 0xC0000093,
    #[error("Integer division by zero")]
    IntegerDivideByZero = 0xC0000094,
    #[error("Integer overflow")]
    IntegerOverflow = 0xC0000095,
    #[error("Privileged instruction")]
    PrivilegedInstruction = 0xC0000096,
    #[error("An attempt was made to install more paging files than the system supports")]
    TooManyPagingFiles = 0xC0000097,
    #[error("The volume for a file has been externally altered such that the opened file is no longer valid")]
    FileInvalid = 0xC0000098,
    #[error("Allotted space exceeded")]
    AllottedSpaceExceeded = 0xC0000099,
    #[error("Insufficient system resources exist to complete the API")]
    InsufficientResources = 0xC000009A,
    #[error("An attempt has been made to open a DFS exit path control file")]
    DfsExitPathFound = 0xC000009B,
    #[error("There are bad blocks (sectors) on the hard disk")]
    DeviceDataError = 0xC000009C,
    #[error("There is bad cabling, non-termination, or the controller is not able to obtain access to the hard disk")]
    DeviceNotConnected = 0xC000009D,
    #[error("Virtual memory cannot be freed because the base address is not the base of the region and a region size of zero was specified")]
    FreeVmNotAtBase = 0xC000009F,
    #[error("An attempt was made to free virtual memory that is not allocated")]
    MemoryNotAllocated = 0xC00000A0,
    #[error("The working set is not big enough to allow the requested pages to be locked")]
    WorkingSetQuota = 0xC00000A1,
    #[error("The disk cannot be written to because it is write-protected")]
    MediaWriteProtected = 0xC00000A2,
    #[error("The drive is not ready for use; its door might be open")]
    DeviceNotReady = 0xC00000A3,
    #[error("The specified attributes are invalid or are incompatible with the attributes for the group as a whole")]
    InvalidGroupAttributes = 0xC00000A4,
    #[error(
        "A specified impersonation level is invalid. Also used to indicate that a required impersonation level was not provided"
    )]
    BadImpersonationLevel = 0xC00000A5,
    #[error(
        "An attempt was made to open an anonymous-level token. Anonymous tokens cannot be opened"
    )]
    CantOpenAnonymous = 0xC00000A6,
    #[error("The validation information class requested was invalid")]
    BadValidationClass = 0xC00000A7,
    #[error("The type of a token object is inappropriate for its attempted use")]
    BadTokenType = 0xC00000A8,
    #[error("The type of a token object is inappropriate for its attempted use")]
    BadMasterBootRecord = 0xC00000A9,
    #[error("An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references")]
    InstructionMisalignment = 0xC00000AA,
    #[error("The maximum named pipe instance count has been reached")]
    InstanceNotAvailable = 0xC00000AB,
    #[error("An instance of a named pipe cannot be found in the listening state")]
    PipeNotAvailable = 0xC00000AC,
    #[error("The named pipe is not in the connected or closing state")]
    InvalidPipeState = 0xC00000AD,
    #[error("The specified pipe is set to complete operations and there are current I/O operations queued so that it cannot be changed to queue operations")]
    PipeBusy = 0xC00000AE,
    #[error("The specified handle is not open to the server end of the named pipe")]
    IllegalFunction = 0xC00000AF,
    #[error("The specified named pipe is in the disconnected state")]
    PipeDisconnected = 0xC00000B0,
    #[error("The specified named pipe is in the closing state")]
    PipeClosing = 0xC00000B1,
    #[error("The specified named pipe is in the connected state")]
    PipeConnected = 0xC00000B2,
    #[error("The specified named pipe is in the listening state")]
    PipeListening = 0xC00000B3,
    #[error("The specified named pipe is not in message mode")]
    InvalidReadMode = 0xC00000B4,
    #[error("Device Timeout")]
    IoTimeout = 0xC00000B5,
    #[error("The specified file has been closed by another process")]
    FileForcedClosed = 0xC00000B6,
    #[error("Profiling is not started")]
    ProfilingNotStarted = 0xC00000B7,
    #[error("Profiling is not stopped")]
    ProfilingNotStopped = 0xC00000B8,
    #[error("The passed ACL did not contain the minimum required information")]
    CouldNotInterpret = 0xC00000B9,
    #[error("The file that was specified as a target is a directory, and the caller specified that it could be anything but a directory")]
    FileIsADirectory = 0xC00000BA,
    #[error("The request is not supported")]
    NotSupported = 0xC00000BB,
    #[error("This remote computer is not listening")]
    RemoteNotListening = 0xC00000BC,
    #[error("A duplicate name exists on the network")]
    DuplicateName = 0xC00000BD,
    #[error("The network path cannot be located")]
    BadNetworkPath = 0xC00000BE,
    #[error("The network is busy")]
    NetworkBusy = 0xC00000BF,
    #[error("This device does not exist")]
    DeviceDoesNotExist = 0xC00000C0,
    #[error("The network BIOS command limit has been reached")]
    TooManyCommands = 0xC00000C1,
    #[error("An I/O adapter hardware error has occurred")]
    AdapterHardwareError = 0xC00000C2,
    #[error("The network responded incorrectly")]
    InvalidNetworkResponse = 0xC00000C3,
    #[error("An unexpected network error occurred")]
    UnexpectedNetworkError = 0xC00000C4,
    #[error("The remote adapter is not compatible")]
    BadRemoteAdapter = 0xC00000C5,
    #[error("The print queue is full")]
    PrintQueueFull = 0xC00000C6,
    #[error(
        "Space to store the file that is waiting to be printed is not available on the server"
    )]
    NoSpoolSpace = 0xC00000C7,
    #[error("The requested print file has been canceled")]
    PrintCancelled = 0xC00000C8,
    #[error("The network name was deleted")]
    NetworkNameDeleted = 0xC00000C9,
    #[error("Network access is denied")]
    NetworkAccessDenied = 0xC00000CA,
    #[error("Incorrect Network Resource Type")]
    BadDeviceType = 0xC00000CB,
    #[error(
        "Network Name Not Found: the specified share name cannot be found on the remote server"
    )]
    BadNetworkName = 0xC00000CC,
    #[error("The name limit for the network adapter card of the local computer was exceeded")]
    TooManyNames = 0xC00000CD,
    #[error("The network BIOS session limit was exceeded")]
    TooManySessions = 0xC00000CE,
    #[error("File sharing has been temporarily paused")]
    SharingPaused = 0xC00000CF,
    #[error("No more connections can be made to this remote computer at this time because the computer has already accepted the maximum number of connections")]
    RequestNotAccepted = 0xC00000D0,
    #[error("Print or disk redirection is temporarily paused")]
    RedirectorPaused = 0xC00000D1,
    #[error("A network data fault occurred")]
    NetWriteFault = 0xC00000D2,
    #[error("The number of active profiling objects is at the maximum and no more can be started")]
    ProfilingAtLimit = 0xC00000D3,
    #[error("Incorrect volume")]
    NotSameDevice = 0xC00000D4,
    #[error("The specified file has been renamed and thus cannot be modified")]
    FileRenamed = 0xC00000D5,
    #[error("Network Request Timeout")]
    VirtualCircuitClosed = 0xC00000D6,
    #[error("Indicates an attempt was made to operate on the security of an object that does not have security associated with it")]
    NoSecurityOnObject = 0xC00000D7,
    #[error("Used to indicate that an operation cannot continue without blocking for I/O")]
    CantWait = 0xC00000D8,
    #[error("Used to indicate that a read operation was done on an empty pipe")]
    PipeEmpty = 0xC00000D9,
    #[error("Configuration information could not be read from the domain controller, either because the machine is unavailable or access has been denied")]
    CantAccessDomainInfo = 0xC00000DA,
    #[error("A thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process")]
    CantTerminateSelf = 0xC00000DB,
    #[error("Indicates the Sam Server was in the wrong state to perform the desired operation")]
    InvalidServerState = 0xC00000DC,
    #[error("Indicates the domain was in the wrong state to perform the desired operation")]
    InvalidDomainState = 0xC00000DD,
    #[error("This operation is only allowed for the primary domain controller of the domain")]
    InvalidDomainRole = 0xC00000DE,
    #[error("The specified domain did not exist.")]
    NoSuchDomain = 0xC00000DF,
    #[error("The specified domain already exists.")]
    DomainExists = 0xC00000E0,
    #[error("An attempt was made to exceed the limit on the number of domains per server for this release")]
    DomainLimitExceeded = 0xC00000E1,
    #[error("An error status returned when the opportunistic lock (oplock) request is denied")]
    OplockNotGranted = 0xC00000E2,
    #[error("An error status returned when an invalid opportunistic lock (oplock) acknowledgment is received by a file system")]
    InvalidOplockProtocol = 0xC00000E3,
    #[error("Requested operation cannot be completed due to a catastrophic media failure or an on-disk data structure corruption")]
    InternalDbCorruption = 0xC00000E4,
    #[error("An internal error occurred")]
    InternalError = 0xC00000E5,
    #[error("Generic access types were contained in an access mask which should already be mapped to non-generic access types")]
    GenericNotMapped = 0xC00000E6,
    #[error("Security descriptor is not in the necessary format (absolute or self-relative")]
    BadDescriptorFormat = 0xC00000E7,
    #[error("An access to a user buffer failed at an expected point in time. This code is defined because the caller does not want to accept STATUS_ACCESS_VIOLATION in its filter")]
    InvalidUserBuffer = 0xC00000E8,
    #[error("Unexpected I/O error")]
    UnexpectedIoError = 0xC00000E9,
    #[error("Unexpected MM create error")]
    UnexpectedMmCreateErr = 0xC00000EA,
    #[error("Unexpected mm map error")]
    UnexpectedMmMapError = 0xC00000EB,
    #[error("Unexpected mm extend error")]
    UnexpectedMmExtendErr = 0xC00000EC,
    #[error("Not logon process")]
    NotLogonProcess = 0xC00000ED,
    #[error("The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process")]
    LogonSessionExists = 0xC00000EE,
    #[error("An attempt was made to access a network file, but the network software was not yet started")]
    RedirectorNotStarted = 0xC00000FB,
    #[error(
        "An attempt was made to start the redirector, but the redirector has already been started"
    )]
    RedirectorStarted = 0xC00000FC,
    #[error("Stack overflow")]
    StackOverflow = 0xC00000FD,
    #[error("A specified authentication package is unknown")]
    NoSuchPackage = 0xC00000FE,
    #[error("A malformed function table was encountered during an unwind operation")]
    BadFunctionTable = 0xC00000FF,
    #[error("Indicates the specified environment variable name was not found in the specified environment block")]
    VariableNotFound = 0xC0000100,
    #[error("Indicates that the directory trying to be deleted is not empty")]
    DirectoryNotEmpty = 0xC0000101,
    #[error("Corrupt File")]
    FileCorruptError = 0xC0000102,
    #[error("A requested opened file is not a directory")]
    NotADirectory = 0xC0000103,
    #[error("The logon session is not in a state that is consistent with the requested operation")]
    BadLogonSessionState = 0xC0000104,
    #[error("An internal LSA error has occurred")]
    LogonSessionCollision = 0xC0000105,
    #[error("A specified name string is too long for its intended use")]
    NameTooLong = 0xC0000106,
    #[error("The user attempted to force close the files on a redirected drive, but there were opened files on the drive, and the user did not specify a sufficient level of force")]
    FilesOpen = 0xC0000107,
    #[error("The user attempted to force close the files on a redirected drive, but there were opened directories on the drive, and the user did not specify a sufficient level of force")]
    ConnectionInUse = 0xC0000108,
    #[error(
        "RtlFindMessage could not locate the requested message ID in the message table resource"
    )]
    MessageNotFound = 0xC0000109,
    #[error("An attempt was made to duplicate an object handle into or out of an exiting process")]
    ProcessIsTerminating = 0xC000010A,
    #[error("An invalid value has been provided for the LogonType requested")]
    InvalidLogonType = 0xC000010B,
    #[error("An attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system")]
    NoGuidTranslation = 0xC000010C,
    #[error(
        "An attempt has been made to impersonate via a named pipe that has not yet been read from"
    )]
    CannotImpersonate = 0xC000010D,
    #[error("Indicates that the specified image is already loaded")]
    ImageAlreadyLoaded = 0xC000010E,
    #[error("An attempt was made to change the size of the LDT for a process that has no LDT")]
    NoLdt = 0xC0000117,
    #[error("The starting value for the LDT information was not an integral multiple of the selector size")]
    InvalidLdtSize = 0xC0000118,
    #[error("The starting value for the LDT information was not an integral multiple of the selector size")]
    InvalidLdtOffset = 0xC0000119,
    #[error(
        "Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors"
    )]
    InvalidLdtDescriptor = 0xC000011A,
    #[error(
        "The specified image file did not have the correct format. It appears to be NE format"
    )]
    InvalidImageNeFormat = 0xC000011B,
    #[error(
        "The transaction state of a registry subtree is incompatible with the requested operation"
    )]
    RxactInvalidState = 0xC000011C,
    #[error("En error has occurred during a registry transaction commit")]
    RxactCommitFailure = 0xC000011D,
    #[error(
        "An attempt was made to map a file of size zero with the maximum size specified as zero"
    )]
    MappedFileSizeZero = 0xC000011E,
    #[error("Too many files are opened on a remote server")]
    TooManyOpenedFiles = 0xC000011F,
    #[error("The I/O request was canceled")]
    Cancelled = 0xC0000120,
    #[error("An attempt has been made to remove a file or directory that cannot be deleted")]
    CannotDelete = 0xC0000121,
    #[error(
        "Indicates a name that was specified as a remote computer name is syntactically invalid"
    )]
    InvalidComputerName = 0xC0000122,
    #[error("An I/O request other than close was performed on a file after it was deleted, which can only happen to a request that did not complete before the last handle was closed via NtClose")]
    FileDeleted = 0xC0000123,
    #[error("Indicates an operation that is incompatible with built-in accounts has been attempted on a built-in (special) SAM account. For example, built-in accounts cannot be deleted")]
    SpecialAccount = 0xC0000124,
    #[error("The operation requested cannot be performed on the specified group because it is a built-in special group")]
    SpecialGroup = 0xC0000125,
    #[error("The operation requested cannot be performed on the specified user because it is a built-in special user")]
    SpecialUser = 0xC0000126,
    #[error("Indicates a member cannot be removed from a group because the group is currently the member's primary group")]
    MembersPrimaryGroup = 0xC0000127,
    #[error("An I/O request other than close and several other special case operations was attempted using a file object that had already been closed")]
    FileClosed = 0xC0000128,
    #[error("Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token can be performed only when a process has zero or one threads")]
    TooManyThreads = 0xC0000129,
    #[error("An attempt was made to operate on a thread within a specific process, but the specified thread is not in the specified process")]
    ThreadNotInProcess = 0xC000012A,
    #[error("An attempt was made to establish a token for use as a primary token but the token is already in use")]
    TokenAlreadyInUse = 0xC000012B,
    #[error("The page file quota was exceeded")]
    PagefileQuotaExceeded = 0xC000012C,
    #[error("Out of Virtual Memory")]
    CommitmentLimit = 0xC000012D,
    #[error(
        "The specified image file did not have the correct format: it appears to be LE format"
    )]
    InvalidImageLeFormat = 0xC000012E,
    #[error(
        "The specified image file did not have the correct format: it did not have an initial MZ"
    )]
    InvalidImageNotMz = 0xC000012F,
    #[error("The specified image file did not have the correct format: it appears to be a 16-bit Windows image")]
    InvalidImageProtect = 0xC0000130,
    #[error("The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role")]
    LogonServerConflict = 0xC0000132,
    #[error("The time at the primary domain controller is different from the time at the backup domain controller or member server by too large an amount")]
    TimeDifferenceAtDc = 0xC0000133,
    #[error("On applicable Windows Server releases, the SAM database is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required")]
    SynchronizationRequired = 0xC0000134,
    #[error("Unable To Locate Component")]
    DllNotFound = 0xC0000135,
    #[error("The NtCreateFile API failed")]
    OpenFailed = 0xC0000136,
    #[error("The I/O permissions for the process could not be changed")]
    IoPrivilegeFailed = 0xC0000137,
    #[error("Ordinal Not Found")]
    OrdinalNotFound = 0xC0000138,
    #[error("Entry Point Not Found")]
    EntrypointNotFound = 0xC0000139,
    #[error("Application Exit by CTRL+C")]
    ControlCExit = 0xC000013A,
    #[error("Virtual Circuit Closed")]
    LocalDisconnect = 0xC000013B,
    #[error("Virtual Circuit Closed")]
    RemoteDisconnect = 0xC000013C,
    #[error("Insufficient Resources on Remote Computer")]
    RemoteResources = 0xC000013D,
    #[error("Virtual Circuit Closed")]
    LinkFailed = 0xC000013E,
    #[error("Virtual Circuit Closed")]
    LinkTimeout = 0xC000013F,
    #[error("The connection handle that was given to the transport was invalid")]
    InvalidConnection = 0xC0000140,
    #[error("The address handle that was given to the transport was invalid")]
    InvalidAddress = 0xC0000141,
    #[error("DLL Initialization Failed")]
    DllInitFailed = 0xC0000142,
    #[error("Missing System File")]
    MissingSystemfile = 0xC0000143,
    #[error("Application Error (unhandled exception)")]
    UnhandledException = 0xC0000144,
    #[error("Application Error (failed to initialize)")]
    AppInitFailure = 0xC0000145,
    #[error("Unable to Create Paging File")]
    PagefileCreateFailed = 0xC0000146,
    #[error("No Paging File Specified")]
    NoPagefile = 0xC0000147,
    #[error("Incorrect System Call Level")]
    InvalidLevel = 0xC0000148,
    #[error("Incorrect Password to LAN Manager Server")]
    WrongPasswordCore = 0xC0000149,
    #[error("real-mode application issued a floating-point instruction and floating-point hardware is not present")]
    IllegalFloatContext = 0xC000014A,
    #[error("The pipe operation has failed because the other end of the pipe has been closed")]
    PipeBroken = 0xC000014B,
    #[error("The Registry Is Corrupt")]
    RegistryCorrupt = 0xC000014C,
    #[error("An I/O operation initiated by the Registry failed and cannot be recovered")]
    RegistryIoFailed = 0xC000014D,
    #[error("An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread")]
    NoEventPair = 0xC000014E,
    #[error("The volume does not contain a recognized file system")]
    UnrecognizedVolume = 0xC000014F,
    #[error("No serial device was successfully initialized")]
    SerialNoDeviceInited = 0xC0000150,
    #[error("The specified local group does not exist")]
    NoSuchAlias = 0xC0000151,
    #[error("The specified account name is not a member of the group")]
    MemberNotInAlias = 0xC0000152,
    #[error("The specified account name is already a member of the group")]
    MemberInAlias = 0xC0000153,
    #[error("The specified local group already exists")]
    AliasExists = 0xC0000154,
    #[error("A requested type of logon is not granted by the local security policy of the target system")]
    LogonNotGranted = 0xC0000155,
    #[error("The maximum number of secrets that can be stored in a single system was exceeded")]
    TooManySecrets = 0xC0000156,
    #[error("The length of a secret exceeds the maximum allowable length")]
    SecretTooLong = 0xC0000157,
    #[error("The local security authority (LSA) database contains an internal inconsistency.")]
    InternalDbError = 0xC0000158,
    #[error("The requested operation cannot be performed in full-screen mode")]
    FullscreenMode = 0xC0000159,
    #[error(
        "During a logon attempt, the user's security context accumulated too many security IDs"
    )]
    TooManyContextIds = 0xC000015A,
    #[error("A user has requested a type of logon that has not been granted")]
    LogonTypeNotGranted = 0xC000015B,
    #[error("The system has attempted to load or restore a file into the registry, and the specified file is not in the format of a registry file")]
    NotRegistryFile = 0xC000015C,
    #[error("An attempt was made to change a user password in the security account manager without providing the necessary Windows cross-encrypted password")]
    NtCrossEncryptionRequired = 0xC000015D,
    #[error("A domain server has an incorrect configuration")]
    DomainCtrlrConfigError = 0xC000015E,
    #[error("An attempt was made to explicitly access the secondary copy of information via a device control to the fault tolerance driver and the secondary copy is not present in the system")]
    FtMissingMember = 0xC000015F,
    #[error("A configuration registry node that represents a driver service entry was ill-formed and did not contain the required value entries")]
    IllFormedServiceEntry = 0xC0000160,
    #[error("An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte")]
    IllegalCharacter = 0xC0000161,
    #[error("No mapping for the Unicode character exists in the target multibyte code page.")]
    UnmappableCharacter = 0xC0000162,
    #[error("The Unicode character is not defined in the Unicode character set that is installed on the system")]
    UndefinedCharacter = 0xC0000163,
    #[error("The paging file cannot be created on a floppy disk")]
    FloppyVolume = 0xC0000164,
    #[error("While accessing a floppy disk, an ID address mark was not found")]
    FloppyIdMarkNotFound = 0xC0000165,
    #[error("While accessing a floppy disk, the track address from the sector ID field was found to be different from the track address that is maintained by the controller")]
    FloppyWrongCylinder = 0xC0000166,
    #[error("The floppy disk controller reported an error that is not recognized by the floppy disk driver")]
    FloppyUnknownError = 0xC0000167,
    #[error("While accessing a floppy-disk, the controller returned inconsistent results via its registers")]
    FloppyBadRegisters = 0xC0000168,
    #[error("While accessing the hard disk, a recalibrate operation failed, even after retries")]
    DiskRecalibrateFailed = 0xC0000169,
    #[error("While accessing the hard disk, a disk operation failed even after retries")]
    DiskOperationFailed = 0xC000016A,
    #[error(
        "While accessing the hard disk, a disk controller reset was needed, but even that failed"
    )]
    DiskResetFailed = 0xC000016B,
    #[error("An attempt was made to open a device that was sharing an interrupt request (IRQ) with other devices")]
    SharedIrqBusy = 0xC000016C,
    #[error("A disk that is part of a fault-tolerant volume can no longer be accessed")]
    FtOrphaning = 0xC000016D,
    #[error("The tape could not be partitioned")]
    PartitionFailure = 0xC0000172,
    #[error(
        "When accessing a new tape of a multi-volume partition, the current blocksize is incorrect"
    )]
    InvalidBlockLength = 0xC0000173,
    #[error("The tape partition information could not be found when loading a tape")]
    DeviceNotPartitioned = 0xC0000174,
    #[error("An attempt to lock the eject media mechanism failed")]
    UnableToLockMedia = 0xC0000175,
    #[error("An attempt to unload media failed")]
    UnableToUnloadMedia = 0xC0000176,
    #[error("The physical end of tape was detected")]
    EomOverflow = 0xC0000177,
    #[error("There is no media in the drive")]
    NoMedia = 0xC0000178,
    #[error("A member could not be added to or removed from the local group because the member does not exist")]
    NoSuchMember = 0xC000017A,
    #[error("A new member could not be added to a local group because the member has the wrong account type")]
    InvalidMember = 0xC000017B,
    #[error(
        "An illegal operation was attempted on a registry key that has been marked for deletion"
    )]
    KeyDeleted = 0xC000017C,
    #[error("The system could not allocate the required space in a registry log")]
    NoLogSpace = 0xC000017D,
    #[error("Too many SIDs have been specified")]
    TooManySids = 0xC000017E,
    #[error("An attempt was made to change a user password in the security account manager without providing the necessary LM cross-encrypted password")]
    LmCrossEncryptionRequired = 0xC000017F,
    #[error("An attempt was made to create a symbolic link in a registry key that already has subkeys or values")]
    KeyHasChildren = 0xC0000180,
    #[error("An attempt was made to create a stable subkey under a volatile parent key")]
    ChildMustBeVolatile = 0xC0000181,
    #[error("The I/O device is configured incorrectly or the configuration parameters to the driver are incorrect")]
    DeviceConfigurationError = 0xC0000182,
    #[error("An error was detected between two drivers or within an I/O driver")]
    DriverInternalError = 0xC0000183,
    #[error("The device is not in a valid state to perform this request")]
    InvalidDeviceState = 0xC0000184,
    #[error("The I/O device reported an I/O error")]
    IoDeviceError = 0xC0000185,
    #[error("A protocol error was detected between the driver and the device")]
    DeviceProtocolError = 0xC0000186,
    #[error("This operation is only allowed for the primary domain controller of the domain")]
    BackupController = 0xC0000187,
    #[error("The log file space is insufficient to support this operation")]
    LogFileFull = 0xC0000188,
    #[error("A write operation was attempted to a volume after it was dismounted")]
    TooLate = 0xC0000189,
    #[error("The workstation does not have a trust secret for the primary domain in the local LSA database")]
    NoTrustLsaSecret = 0xC000018A,
    #[error("On applicable Windows Server releases, the SAM database does not have a computer account for this workstation trust relationship")]
    NoTrustSamAccount = 0xC000018B,
    #[error("The logon request failed because the trust relationship between the primary domain and the trusted domain failed")]
    TrustedDomainFailure = 0xC000018C,
    #[error("The logon request failed because the trust relationship between this workstation and the primary domain failed")]
    TrustedRelationshipFailure = 0xC000018D,
    #[error("The Eventlog log file is corrupt")]
    EventlogFileCorrupt = 0xC000018E,
    #[error("No Eventlog log file could be opened. The Eventlog service did not start")]
    EventlogCantStart = 0xC000018F,
    #[error("The network logon failed. This might be because the validation authority cannot be reached")]
    TrustFailure = 0xC0000190,
    #[error("An attempt was made to acquire a mutant such that its maximum count would have been exceeded")]
    MutantLimitExceeded = 0xC0000191,
    #[error("An attempt was made to logon, but the NetLogon service was not started")]
    NetlogonNotStarted = 0xC0000192,
    #[error("The user account has expired")]
    AccountExpired = 0xC0000193,
    #[error("Possible deadlock condition")]
    PossibleDeadlock = 0xC0000194,
    #[error("Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed")]
    NetworkCredentialConflict = 0xC0000195,
    #[error("An attempt was made to establish a session to a network server, but there are already too many sessions established to that server")]
    RemoteSessionLimit = 0xC0000196,
    #[error("The log file has changed between reads")]
    EventlogFileChanged = 0xC0000197,
    #[error("The account used is an interdomain trust account. Use your global user account or local user account to access this server")]
    NologonInterdomainTrustAc = 0xC0000198,
    #[error("The account used is a computer account. Use your global user account or local user account to access this server")]
    NologonWorkstationTrustAc = 0xC0000199,
    #[error("The account used is a server trust account. Use your global user account or local user account to access this server")]
    NologonServerTrustAccount = 0xC000019A,
    #[error("The name or SID of the specified domain is inconsistent with the trust information for that domain")]
    DomainTrustInconsistent = 0xC000019B,
    #[error("A volume has been accessed for which a file system driver is required that has not yet been loaded")]
    FsDriverRequired = 0xC000019C,
    #[error("Indicates that the specified image is already loaded as a DLL")]
    NoUserSessionKey = 0xC0000202,
    #[error("There is no user session key for the specified logon session")]
    UserSessionDeleted = 0xC0000203,
    #[error("The remote user session has been deleted.")]
    ResourceLangNotFound = 0xC0000204,
    #[error("Indicates the specified resource language ID cannot be found in the image file")]
    InsuffServerResources = 0xC0000205,
    #[error("The size of the buffer is invalid for the specified operation")]
    InvalidBufferSize = 0xC0000206,
    #[error("The transport rejected the specified network address as invalid")]
    InvalidAddressComponent = 0xC0000207,
    #[error("The transport rejected the specified network address as invalid")]
    InvalidAddressWildcard = 0xC0000208,
    #[error(
        "The transport address could not be opened because all the available addresses are in use"
    )]
    TooManyAddresses = 0xC0000209,
    #[error("The transport address could not be opened because it already exists")]
    AddressAlreadyExists = 0xC000020A,
    #[error("The transport address is now closed.")]
    AddressClosed = 0xC000020B,
    #[error("The transport connection is now disconnected")]
    ConnectionDisconnected = 0xC000020C,
    #[error("The transport connection has been reset")]
    ConnectionReset = 0xC000020D,
    #[error("The transport cannot dynamically acquire any more nodes")]
    TooManyNodes = 0xC000020E,
    #[error("The transport aborted a pending transaction")]
    TransactionAborted = 0xC000020F,
    #[error("The transport timed out a request that is waiting for a response")]
    TransactionTimedOut = 0xC0000210,
    #[error("The transport did not receive a release for a pending response")]
    TransactionNoRelease = 0xC0000211,
    #[error("The transport did not find a transaction that matches the specific token")]
    TransactionNoMatch = 0xC0000212,
    #[error("The transport had previously responded to a transaction request")]
    TransactionResponded = 0xC0000213,
    #[error("The transport does not recognize the specified transaction request ID")]
    TransactionInvalidId = 0xC0000214,
    #[error("The transport does not recognize the specified transaction request type")]
    TransactionInvalidType = 0xC0000215,
    #[error(
        "The transport can only process the specified request on the server side of a session"
    )]
    NotServerSession = 0xC0000216,
    #[error(
        "The transport can only process the specified request on the client side of a session"
    )]
    NotClientSession = 0xC0000217,
    #[error("The registry cannot load the hive")]
    CannotLoadRegistryFile = 0xC0000218,
    #[error("Unexpected Failure in DebugActiveProcess")]
    DebugAttachFailed = 0xC0000219,
    #[error("Fatal System Error")]
    SystemProcessTerminated = 0xC000021A,
    #[error("The TDI client could not handle the data received during an indication")]
    DataNotAccepted = 0xC000021B,
    #[error("The list of servers for this workgroup is not currently available")]
    NoBrowserServersFound = 0xC000021C,
    #[error("NTVDM encountered a hard error")]
    VdmHardError = 0xC000021D,
    #[error("Cancel Timeout")]
    DriverCancelTimeout = 0xC000021E,
    #[error("An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message")]
    ReplyMessageMismatch = 0xC000021F,
    #[error("Mapped View Alignment Incorrect")]
    MappedAlignment = 0xC0000220,
    #[error("Bad Image Checksum")]
    ImageChecksumMismatch = 0xC0000221,
    #[error("Delayed Write Failed")]
    LostWritebehindData = 0xC0000222,
    #[error("The parameters passed to the server in the client/server shared memory window were invalid")]
    ClientServerParametersInv = 0xC0000223,
    #[error("The user password must be changed before logging on the first time")]
    PasswordMustChange = 0xC0000224,
    #[error("The object was not found")]
    NotFound = 0xC0000225,
    #[error("The stream is not a tiny stream")]
    NotTinyStream = 0xC0000226,
    #[error("A transaction recovery failed")]
    RecoveryFailure = 0xC0000227,
    #[error("The request must be handled by the stack overflow code")]
    StackOverflowRead = 0xC0000228,
    #[error("A consistency check failed")]
    FailCheck = 0xC0000229,
    #[error(
        "The attempt to insert the ID in the index failed because the ID is already in the index"
    )]
    DuplicateObjectid = 0xC000022A,
    #[error("The attempt to set the object ID failed because the object already has an ID")]
    ObjectidExists = 0xC000022B,
    #[error("Internal OFS status codes indicating how an allocation operation is handled")]
    ConvertToLarge = 0xC000022C,
    #[error("The request needs to be retried")]
    Retry = 0xC000022D,
    #[error("The attempt to find the object found an object on the volume that matches by ID")]
    FoundOutOfScope = 0xC000022E,
    #[error("The bucket array must be grown. Retry the transaction after doing so")]
    AllocateBucket = 0xC000022F,
    #[error("The specified property set does not exist on the object")]
    PropsetNotFound = 0xC0000230,
    #[error("The user/kernel marshaling buffer has overflowed")]
    MarshallOverflow = 0xC0000231,
    #[error("The supplied variant structure contains invalid data")]
    InvalidVariant = 0xC0000232,
    #[error("A domain controller for this domain was not found")]
    DomainControllerNotFound = 0xC0000233,
    #[error("The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested")]
    AccountLockedOut = 0xC0000234,
    #[error(
        "NtClose was called on a handle that was protected from close via NtSetInformationObject"
    )]
    HandleNotClosable = 0xC0000235,
    #[error("The transport-connection attempt was refused by the remote system")]
    ConnectionRefused = 0xC0000236,
    #[error("The transport connection was gracefully closed")]
    GracefulDisconnect = 0xC0000237,
    #[error("The transport endpoint already has an address associated with it")]
    AddressAlreadyAssociated = 0xC0000238,
    #[error("An address has not yet been associated with the transport endpoint")]
    AddressNotAssociated = 0xC0000239,
    #[error("An operation was attempted on a nonexistent transport connection")]
    ConnectionInvalid = 0xC000023A,
    #[error("An invalid operation was attempted on an active transport connection")]
    ConnectionActive = 0xC000023B,
    #[error("The remote network is not reachable by the transport")]
    NetworkUnreachable = 0xC000023C,
    #[error("The remote system is not reachable by the transport")]
    HostUnreachable = 0xC000023D,
    #[error("The remote system does not support the transport protocol")]
    ProtocolUnreachable = 0xC000023E,
    #[error(
        "No service is operating at the destination port of the transport on the remote system"
    )]
    PortUnreachable = 0xC000023F,
    #[error("The request was aborted")]
    RequestAborted = 0xC0000240,
    #[error("The transport connection was aborted by the local system")]
    ConnectionAborted = 0xC0000241,
    #[error("The specified buffer contains ill-formed data")]
    BadCompressionBuffer = 0xC0000242,
    #[error(
        "The requested operation cannot be performed on a file with a user mapped section open"
    )]
    UserMappedFile = 0xC0000243,
    #[error("An attempt to generate a security audit failed")]
    AuditFailed = 0xC0000244,
    #[error("The timer resolution was not previously set by the current process")]
    TimerResolutionNotSet = 0xC0000245,
    #[error("A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached")]
    ConnectionCountLimit = 0xC0000246,
    #[error("Attempting to log on during an unauthorized time of day for this account")]
    LoginTimeRestriction = 0xC0000247,
    #[error("The account is not authorized to log on from this station")]
    LoginWkstaRestriction = 0xC0000248,
    #[error("UP/MP Image Mismatch")]
    ImageMpUpMismatch = 0xC0000249,
    #[error("There is insufficient account information to log you on")]
    InsufficientLogonInfo = 0xC0000250,
    #[error("Invalid DLL Entrypoint")]
    BadDllEntrypoint = 0xC0000251,
    #[error("Invalid Service Callback Entrypoint")]
    BadServiceEntrypoint = 0xC0000252,
    #[error("The server received the messages but did not send a reply")]
    LpcReplyLost = 0xC0000253,
    #[error("There is an IP address conflict with another system on the network")]
    IpAddressConflict1 = 0xC0000254,
    #[error("There is an IP address conflict with another system on the network")]
    IpAddressConflict2 = 0xC0000255,
    #[error("Low On Registry Space")]
    RegistryQuotaLimit = 0xC0000256,
    #[error("The contacted server does not support the indicated part of the DFS namespace")]
    PathNotCovered = 0xC0000257,
    #[error("A callback return system service cannot be executed when no callback is active")]
    NoCallbackActive = 0xC0000258,
    #[error("The service being accessed is licensed for a particular number of connections")]
    LicenseQuotaExceeded = 0xC0000259,
    #[error("The password provided is too short to meet the policy of your user account")]
    PwdTooShort = 0xC000025A,
    #[error(
        "The policy of your user account does not allow you to change passwords too frequently"
    )]
    PwdTooRecent = 0xC000025B,
    #[error("You have attempted to change your password to one that you have used in the past")]
    PwdHistoryConflict = 0xC000025C,
    #[error("You have attempted to load a legacy device driver while its device instance had been disabled")]
    PlugplayNoDevice = 0xC000025E,
    #[error("The specified hardware profile configuration is invalid")]
    UnsupportedCompression = 0xC000025F,
    #[error("The specified hardware profile configuration is invalid.")]
    InvalidHwProfile = 0xC0000260,
    #[error("The specified Plug and Play registry device path is invalid")]
    InvalidPlugplayDevicePath = 0xC0000261,
    #[error("Driver Entry Point Not Found")]
    DriverOrdinalNotFound = 0xC0000262,
    #[error("Driver Entry Point Not Found")]
    DriverEntrypointNotFound = 0xC0000263,
    #[error("The application attempted to release a resource it did not own")]
    ResourceNotOwned = 0xC0000264,
    #[error("An attempt was made to create more links on a file than the file system supports")]
    TooManyLinks = 0xC0000265,
    #[error("The specified quota list is internally inconsistent with its descriptor")]
    QuotaListInconsistent = 0xC0000266,
    #[error("The specified file has been relocated to offline storage")]
    FileIsOffline = 0xC0000267,
    #[error("An operation was attempted to a volume after it was dismounted")]
    VolumeDismounted = 0xC000026E,
    #[error("The NTFS file or directory is not a reparse point")]
    NotAReparsePoint = 0xC0000275,
    #[error("Stopped on symlink")]
    StoppedOnSymlink = 0x8000002d,
    #[error("Unknown error")]
    UnknownError,
}

impl From<u32> for ErrorCode {
    fn from(status: u32) -> Self {
        match num::FromPrimitive::from_u32(status) {
            Some(err) => err,
            None => ErrorCode::UnknownError,
        }
    }
}

impl From<ErrorCode> for u32 {
    fn from(code: ErrorCode) -> u32 {
        code as u32
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_errors_errorcode() {
        // Try from
        assert_eq!(ErrorCode::from(0x8000002d), ErrorCode::StoppedOnSymlink);
        assert_eq!(ErrorCode::from(0x00000000), ErrorCode::Success);
        assert_eq!(ErrorCode::from(0xcafebabe), ErrorCode::UnknownError);
        // To u32
        let code: u32 = From::from(ErrorCode::Success);
        assert_eq!(code, 0);
        let code: u32 = From::from(ErrorCode::StoppedOnSymlink);
        assert_eq!(code, 0x8000002d);
    }
}
