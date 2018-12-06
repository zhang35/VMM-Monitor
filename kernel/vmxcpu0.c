#include "ntddk.h"

#define IA32_VMX_BASIC_MSR_CODE			0x480
#define IA32_FEATURE_CONTROL_CODE		0x03A

//////////////////
//              //
//  PROTOTYPES  //
//              //
//////////////////
NTSTATUS	DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath );
VOID		DriverUnload( IN PDRIVER_OBJECT DriverObject );
VOID		StartVMX( );
VOID		VMMEntryPoint( );

////////////////////
//                //
//  VMX FEATURES  //
//                //
////////////////////
typedef struct _VMX_FEATURES
{
	unsigned SSE3		:1;		// SSE3 Extensions
	unsigned RES1		:2;
	unsigned MONITOR	:1;		// MONITOR/WAIT
	unsigned DS_CPL		:1;		// CPL qualified Debug Store
	unsigned VMX		:1;		// Virtual Machine Technology
	unsigned RES2		:1;
	unsigned EST		:1;		// Enhanced Intel?Speedstep Technology
	unsigned TM2		:1;		// Thermal monitor 2
	unsigned SSSE3		:1;		// SSSE3 extensions
	unsigned CID		:1;		// L1 context ID
	unsigned RES3		:2;
	unsigned CX16		:1;		// CMPXCHG16B
	unsigned xTPR		:1;		// Update control
	unsigned PDCM		:1;		// Performance/Debug capability MSR
	unsigned RES4		:2;
	unsigned DCA		:1;
	unsigned RES5		:13;
	
} VMX_FEATURES;

//////////////
//          //
//  EFLAGS  //
//          //
//////////////
typedef struct _EFLAGS
{
	unsigned Reserved1	:10;
	unsigned ID			:1;		// Identification flag
	unsigned VIP		:1;		// Virtual interrupt pending
	unsigned VIF		:1;		// Virtual interrupt flag
	unsigned AC			:1;		// Alignment check
	unsigned VM			:1;		// Virtual 8086 mode
	unsigned RF			:1;		// Resume flag
	unsigned Reserved2	:1;
	unsigned NT			:1;		// Nested task flag
	unsigned IOPL		:2;		// I/O privilege level
	unsigned OF			:1;
	unsigned DF			:1;
	unsigned IF			:1;		// Interrupt flag
	unsigned TF			:1;		// Task flag
	unsigned SF			:1;		// Sign flag
	unsigned ZF			:1;		// Zero flag
	unsigned Reserved3	:1;
	unsigned AF			:1;		// Borrow flag
	unsigned Reserved4	:1;
	unsigned PF			:1;		// Parity flag
	unsigned Reserved5	:1;
	unsigned CF			:1;		// Carry flag [Bit 0]

} EFLAGS;

///////////
//       //
//  MSR  //
//       //
///////////
//MSR 是CPU 的一组64 位寄存器,为了设置CPU 的工作环境和标示CPU 的工作状态
typedef struct _MSR
{
	ULONG		Hi;
	ULONG		Lo;
} MSR;

/////////////////////////////
//                         //
//  SPECIAL MSR REGISTERS  //
//                         //
/////////////////////////////
typedef struct _IA32_VMX_BASIC_MSR
{

	unsigned RevId			:32;	// Bits 31...0 contain the VMCS revision identifier
	unsigned szVmxOnRegion  :12;	// Bits 43...32 report # of bytes for VMXON region 
	unsigned RegionClear	:1;		// Bit 44 set only if bits 32-43 are clear
	unsigned Reserved1		:3;		// Undefined
	unsigned PhyAddrWidth	:1;		// Physical address width for referencing VMXON, VMCS, etc.
	unsigned DualMon		:1;		// Reports whether the processor supports dual-monitor
									// treatment of SMI and SMM
	unsigned MemType		:4;		// Memory type that the processor uses to access the VMCS
	unsigned VmExitReport	:1;		// Reports weather the procesor reports info in the VM-exit
									// instruction information field on VM exits due to execution
									// of the INS and OUTS instructions
	unsigned Reserved2		:9;		// Undefined

} IA32_VMX_BASIC_MSR;


typedef struct _IA32_FEATURE_CONTROL_MSR
{
	unsigned Lock			:1;		// Bit 0 is the lock bit - cannot be modified once lock is set
	unsigned Reserved1		:1;		// Undefined
	unsigned EnableVmxon	:1;		// Bit 2. If this bit is clear, VMXON causes a general protection exception
	unsigned Reserved2		:29;	// Undefined
	unsigned Reserved3		:32;	// Undefined

} IA32_FEATURE_CONTROL_MSR;

/////////////////////////
//                     //
//  CONTROL REGISTERS  //
//                     //
/////////////////////////
typedef struct _CR0_REG
{
	unsigned PE			:1;			// Protected Mode Enabled [Bit 0]
	unsigned MP			:1;			// Monitor Coprocessor FLAG
	unsigned EM			:1;			// Emulate FLAG
	unsigned TS			:1;			// Task Switched FLAG
	unsigned ET			:1;			// Extension Type FLAG
	unsigned NE			:1;			// Numeric Error
	unsigned Reserved1	:10;		// 
	unsigned WP			:1;			// Write Protect
	unsigned Reserved2	:1;			// 
	unsigned AM			:1;			// Alignment Mask
	unsigned Reserved3	:10;		// 
	unsigned NW			:1;			// Not Write-Through
	unsigned CD			:1;			// Cache Disable
	unsigned PG			:1;			// Paging Enabled

} CR0_REG;

typedef struct _CR4_REG
{
	unsigned VME		:1;			// Virtual Mode Extensions
	unsigned PVI		:1;			// Protected-Mode Virtual Interrupts
	unsigned TSD		:1;			// Time Stamp Disable
	unsigned DE			:1;			// Debugging Extensions
	unsigned PSE		:1;			// Page Size Extensions
	unsigned PAE		:1;			// Physical Address Extension
	unsigned MCE		:1;			// Machine-Check Enable
	unsigned PGE		:1;			// Page Global Enable
	unsigned PCE		:1;			// Performance-Monitoring Counter Enable
	unsigned OSFXSR		:1;			// OS Support for FXSAVE/FXRSTOR
	unsigned OSXMMEXCPT	:1;			// OS Support for Unmasked SIMD Floating-Point Exceptions
	unsigned Reserved1	:2;			// 
	unsigned VMXE		:1;			// Virtual Machine Extensions Enabled
	unsigned Reserved2	:18;		// 

} CR4_REG;

/////////////////
//             //
//  MISC DATA  //
//             //
/////////////////
typedef struct _MISC_DATA
{
	unsigned	Reserved1		:6;		// [0-5]
	unsigned	ActivityStates	:3;		// [6-8]
	unsigned	Reserved2		:7;		// [9-15]
	unsigned	CR3Targets		:9;		// [16-24]

	// 512*(N+1) is the recommended maximum number of MSRs
	unsigned	MaxMSRs			:3;		// [25-27]

	unsigned	Reserved3		:4;		// [28-31]
	unsigned	MSEGRevID		:32;	// [32-63]

} MISC_DATA;

//////////////////////////
//                      //
//  SELECTOR REGISTERS  //
//                      //
//////////////////////////
typedef struct _GDTR
{
	unsigned	Limit		:16;
	unsigned	BaseLo		:16;
	unsigned	BaseHi		:16;

} GDTR;

typedef struct _IDTR
{
	unsigned	Limit		:16;
	unsigned	BaseLo		:16;
	unsigned	BaseHi		:16;

} IDTR;

typedef struct	_SEG_DESCRIPTOR
{
	unsigned	LimitLo	:16;
	unsigned	BaseLo	:16;
	unsigned	BaseMid	:8;
	unsigned	Type	:4;
	unsigned	System	:1;
	unsigned	DPL		:2;
	unsigned	Present	:1;
	unsigned	LimitHi	:4;
	unsigned	AVL		:1;
	unsigned	L		:1;
	unsigned	DB		:1;
	unsigned	Gran	:1;		// Granularity
	unsigned	BaseHi	:8;
	
} SEG_DESCRIPTOR;

///////////////
//           //
//  Globals  //
//           //
///////////////
ULONG			*pVMXONRegion		= NULL;		// Memory address of VMXON region.
ULONG			*pVMCSRegion		= NULL;		// Memory address of VMCS region.
ULONG			VMXONRegionSize		= 0;		// Size of of VMXON region.
ULONG			VMCSRegionSize		= 0;		// Size of of VMCS region.
ULONG			ErrorCode			= 0;

EFLAGS						eFlags				= {0};
MSR							msr					= {0};

PVOID						FakeStack			= NULL;

ULONG						HandlerLogging		= 0;
ULONG						ScrubTheLaunch		= 0;
ULONG						VMXIsActive			= 0;

PHYSICAL_ADDRESS			PhysicalVMXONRegionPtr = {0};
PHYSICAL_ADDRESS			PhysicalVMCSRegionPtr = {0};

VMX_FEATURES				vmxFeatures;
IA32_VMX_BASIC_MSR			vmxBasicMsr ;
IA32_FEATURE_CONTROL_MSR	vmxFeatureControl ;

CR0_REG						cr0_reg = {0};
CR4_REG						cr4_reg = {0};

ULONG						temp32 = 0;
USHORT						temp16 = 0;

GDTR						gdt_reg = {0};
IDTR						idt_reg = {0};

ULONG						gdt_base = 0;
ULONG						idt_base = 0;

USHORT						mLDT = 0;
USHORT						seg_selector = 0;

SEG_DESCRIPTOR				segDescriptor = {0};
MISC_DATA					misc_data = {0};

PVOID						GuestReturn = NULL;
ULONG						GuestStack = 0;

///////////
//       //
//  Log  //
//       //
///////////
#define Log( message, value ) { DbgPrint("[vmm] %-40s [%08X]\n", message, value ); }

///////////////
//           //
//  SET BIT  //
//           //
///////////////
VOID SetBit( ULONG * dword, ULONG bit )//把相应的位置1
{
	ULONG mask = ( 1 << bit );
	*dword = *dword | mask;
}

/////////////////
//             //
//  CLEAR BIT  //
//             //
/////////////////
VOID ClearBit( ULONG * dword, ULONG bit )//把相应位置0
{
	ULONG mask = 0xFFFFFFFF;
	ULONG sub = ( 1 << bit );
	mask = mask - sub;
	*dword = *dword & mask;
}

//	Writes the 'value' into the VMCS region specified by 'encoding'VMWRITE<索引><数据>
//
VOID WriteVMCS( ULONG encoding, ULONG value )//把VALUE的值写入ENCODING指定的VMCS区域
{
	__asm
	{
		PUSHAD
		
		PUSH	value
		MOV		EAX, encoding 

		_emit	0x0F				// VMWRITE EAX, [ESP]
		_emit	0x79
		_emit	0x04
		_emit	0x24
		
		POP EAX
		
		POPAD
	}
}

//	Loads the contents of a 64-bit model specific register (MSR) specified
//	in the ECX register into registers EDX:EAX. The EDX register is loaded
//	with the high-order 32 bits of the MSR and the EAX register is loaded
//	with the low-order 32 bits.
//		msr.Hi --> EDX
//		msr.Lo --> EAX
//
VOID ReadMSR( ULONG msrEncoding )//把指定编号的MSR读人到msr结构里面
{
	__asm
	{
		PUSHAD
			
		MOV		ECX, msrEncoding

		RDMSR

		MOV		msr.Hi, EDX
		MOV		msr.Lo, EAX

		POPAD
	}
}

//	Writes the contents of registers EDX:EAX into the 64-bit model specific
//	register (MSR) specified in the ECX register. The contents of the EDX
//	register are copied to high-order 32 bits of the selected MSR and the
//	contents of the EAX register are copied to low-order 32 bits of the MSR.
//		msr.Hi <-- EDX
//		msr.Lo <-- EAX
//
VOID WriteMSR( ULONG msrEncoding )
{
	__asm
	{
		PUSHAD

		MOV		EDX, msr.Hi
		MOV		EAX, msr.Lo
		MOV		ECX, msrEncoding

		WRMSR

		POPAD
	}
}

////////////////////////////////////
//                                //
//  SEGMENT DESCRIPTOR OPERATORS  //
//                                //
////////////////////////////////////
ULONG GetSegmentDescriptorBase( ULONG gdt_base , USHORT seg_selector )
{
	ULONG			base = 0;
	SEG_DESCRIPTOR	segDescriptor = {0};
	
	RtlCopyBytes( &segDescriptor, (ULONG *)(gdt_base + (seg_selector >> 3) * 8), 8 );
	base = segDescriptor.BaseHi;
	base <<= 8;
	base |= segDescriptor.BaseMid;
	base <<= 16;
	base |= segDescriptor.BaseLo;

	return base;
}

//DPL：访问目标代码段所需的级别。定义在 segment descriptor 的 DPL 域中
ULONG GetSegmentDescriptorDPL( ULONG gdt_base , USHORT seg_selector )
{
	SEG_DESCRIPTOR	segDescriptor = {0};
	
	RtlCopyBytes( &segDescriptor, (ULONG *)(gdt_base + (seg_selector >> 3) * 8), 8 );
	
	return segDescriptor.DPL;
}

ULONG GetSegmentDescriptorLimit( ULONG gdt_base , USHORT seg_selector )
{
	SEG_DESCRIPTOR	segDescriptor = {0};
	
	RtlCopyBytes( &segDescriptor, (ULONG *)(gdt_base + (seg_selector >> 3) * 8), 8 );
	
	return ( (segDescriptor.LimitHi << 16) | segDescriptor.LimitLo );
}

///////////
//       //
//	VMX  //
//       //
///////////
__declspec( naked ) VOID StartVMX( )
{	

	__asm	POP	GuestReturn

	Log("Guest Return EIP" , GuestReturn );

	///////////////////////////
	//                       //
	//	SET THREAD AFFINITY  //
	//                       //
	///////////////////////////
	Log( "Enabling VMX mode on CPU 0", 0 );
	KeSetSystemAffinityThread( (KAFFINITY) 0x00000001 );
	Log( "Running on Processor" , KeGetCurrentProcessorNumber() );

	//初始化 GDT , IDT 
	////////////////
	//            //
	//  GDT Info  //
	//            //
	////////////////
	__asm
	{
		SGDT	gdt_reg
	}

	temp32 = 0;
	temp32 = gdt_reg.BaseHi;
	temp32 <<= 16;
	temp32 |= gdt_reg.BaseLo;
	gdt_base = temp32;
	Log( "GDT Base", gdt_base );
	Log( "GDT Limit", gdt_reg.Limit );
	
	////////////////////////////
	//                        //
	//  IDT Segment Selector  //
	//                        //
	////////////////////////////
	__asm	SIDT	idt_reg
	
	temp32 = 0;
	temp32 = idt_reg.BaseHi;
	temp32 <<= 16;
	temp32 |= idt_reg.BaseLo;
	idt_base = temp32;
	Log( "IDT Base", idt_base );
	Log( "IDT Limit", idt_reg.Limit );

	//	(1)	Check VMX support in processor using CPUID.用CPUID指令查看是否支持虚拟化
	__asm
	{
		PUSHAD
		
		MOV		EAX, 1//CPUID指令用来获取CPU的信息，把EAX当成输入参数
		CPUID
		
		// ECX contains the VMX_FEATURES FLAGS (VMX supported if bit 5 equals 1)
		MOV		vmxFeatures, ECX

		MOV		EAX, 0x80000008
		CPUID
		MOV		temp32, EAX
		
		POPAD
	}

	if( vmxFeatures.VMX == 0 )
	{
		Log( "VMX Support Not Present." , vmxFeatures );
		goto Abort;
	}
	
	Log( "VMX Support Present." , vmxFeatures );
	
	//	(2)	Determine the VMX capabilities supported by the processor through
	//		the VMX capability MSRs.
	__asm
	{
		PUSHAD

		MOV		ECX, IA32_VMX_BASIC_MSR_CODE
		RDMSR
		LEA		EBX, vmxBasicMsr
		MOV		[EBX+4], EDX
		MOV		[EBX], EAX

		MOV		ECX, IA32_FEATURE_CONTROL_CODE
		RDMSR
		LEA		EBX, vmxFeatureControl
		MOV		[EBX+4], EDX
		MOV		[EBX], EAX

		POPAD
	};

	//	(3)	Create a VMXON region in non-pageable memory of a size specified by
	//		IA32_VMX_BASIC_MSR and aligned to a 4-byte boundary. The VMXON region
	//		must be hosted in cache-coherent memory.
	Log( "VMXON Region Size" , vmxBasicMsr.szVmxOnRegion ) ;
	Log( "VMXON Access Width Bit" , vmxBasicMsr.PhyAddrWidth );
	Log( "      [   1] --> 32-bit" , 0 );
	Log( "      [   0] --> 64-bit" , 0 );
	Log( "VMXON Memory Type", vmxBasicMsr.MemType );
	Log( "      [   0]  --> Strong Uncacheable" , 0 );
	Log( "      [ 1-5]  --> Unused" , 0 );
	Log( "      [   6]  --> Write Back" , 0 );
	Log( "      [7-15]  --> Unused" , 0 );

	VMXONRegionSize = vmxBasicMsr.szVmxOnRegion;
	
	switch( vmxBasicMsr.MemType )
	{
		case 0:
			Log( "Unsupported memory type." , vmxBasicMsr.MemType );
			goto Abort;
			break;
		case 6:
			break;
		default:
			Log( "ERROR : Unknown VMXON Region memory type." , 0);
			goto Abort;
			break;
	}

	//	(4)	Initialize the version identifier in the VMXON region (first 32 bits)
	//		with the VMCS revision identifier reported by capability MSRs.
	*(pVMXONRegion) = vmxBasicMsr.RevId;
	
	Log( "vmxBasicMsr.RevId" , vmxBasicMsr.RevId );

	//	(5)	Ensure the current processor operating mode meets the required CR0
	//		fixed bits (CR0.PE=1, CR0.PG=1). Other required CR0 fixed bits can
	//		be detected through the IA32_VMX_CR0_FIXED0 and IA32_VMX_CR0_FIXED1
	//		MSRs.通过CR0判断处理器是否在分段和分页模式
	__asm
	{
		PUSH	EAX

		MOV		EAX, CR0
		MOV		cr0_reg, EAX
		
		POP		EAX
	}
	if( cr0_reg.PE != 1 )
	{
		Log( "ERROR : Protected Mode not enabled." , 0 );
		Log( "Value of CR0" , cr0_reg );
		goto Abort;
	}

	Log( "Protected Mode enabled." , 0 );

	if( cr0_reg.PG != 1 )
	{
		Log( "ERROR : Paging not enabled." , 0 );
		Log( "Value of CR0" , cr0_reg );
		goto Abort;
	}
	
	Log( "Paging enabled." , 0 );
	
	cr0_reg.NE = 1;

	__asm
	{
		PUSH	EAX
		
		MOV		EAX, cr0_reg
		MOV		CR0, EAX
		
		POP		EAX
	}

	//	(6)	Enable VMX operation by setting CR4.VMXE=1 [bit 13]. Ensure the
	//		resultant CR4 value supports all the CR4 fixed bits reported in
	//		the IA32_VMX_CR4_FIXED0 and IA32_VMX_CR4_FIXED1 MSRs.修改CR4，以允许VMX操作
	__asm
	{
		PUSH	EAX

		_emit	0x0F	// MOV	EAX, CR4
		_emit	0x20
		_emit	0xE0
		
		MOV		cr4_reg, EAX

		POP		EAX
	}

	Log( "CR4" , cr4_reg );
	cr4_reg.VMXE = 1;
	Log( "CR4" , cr4_reg );

	__asm
	{
		PUSH	EAX

		MOV		EAX, cr4_reg
		
		_emit	0x0F	// MOV	CR4, EAX
		_emit	0x22
		_emit	0xE0
		
		POP		EAX
	}
	
	//	(7)	Ensure that the IA32_FEATURE_CONTROL_MSR (MSR index 0x3A) has been
	//		properly programmed and that its lock bit is set (bit 0=1). This MSR
	//		is generally configured by the BIOS using WRMSR.
	Log( "IA32_FEATURE_CONTROL Lock Bit" , vmxFeatureControl.Lock );
	if( vmxFeatureControl.Lock != 1 )
	{
		Log( "ERROR : Feature Control Lock Bit != 1." , 0 );
		goto Abort;
	}

	//	(8)	Execute VMXON with the physical address of the VMXON region as the
	//		operand. Check successful execution of VMXON by checking if
	//		RFLAGS.CF=0.
	__asm
	{
		PUSH	DWORD PTR 0
		PUSH	DWORD PTR PhysicalVMXONRegionPtr.LowPart
		
		_emit	0xF3	// VMXON [ESP]
		_emit	0x0F
		_emit	0xC7
		_emit	0x34
		_emit	0x24

		PUSHFD
		POP		eFlags

		ADD		ESP, 8
	}
	if( eFlags.CF == 1 )
	{
		Log( "ERROR : VMXON operation failed." , 0 );
		goto Abort;
	}
	
	Log( "SUCCESS : VMXON operation completed." , 0 );
	Log( "VMM is now running." , 0 );
	
	VMXIsActive = 1;
	
	//
	//	***	The processor is now in VMX root operation!
	//

	//	(1)	Create a VMCS region in non-pageable memory of size specified by
	//		the VMX capability MSR IA32_VMX_BASIC and aligned to 4-KBytes.
	//		Software should read the capability MSRs to determine width of the 
	//		physical addresses that may be used for a VMCS region and ensure
	//		the entire VMCS region can be addressed by addresses with that width.
	//		The term "guest-VMCS address" refers to the physical address of the
	//		new VMCS region for the following steps.
	VMCSRegionSize = vmxBasicMsr.szVmxOnRegion;
	
	switch( vmxBasicMsr.MemType )
	{
		case 0:
			Log( "Unsupported memory type." , vmxBasicMsr.MemType );
			goto Abort;
			break;
		case 6:
			break;
		default:
			Log( "ERROR : Unknown VMCS Region memory type." , 0 );
			goto Abort;
			break;
	}
	
	//	(2)	Initialize the version identifier in the VMCS (first 32 bits)
	//		with the VMCS revision identifier reported by the VMX
	//		capability MSR IA32_VMX_BASIC.
	*(pVMCSRegion) = vmxBasicMsr.RevId;

	//	(3)	Execute the VMCLEAR instruction by supplying the guest-VMCS address.
	//		This will initialize the new VMCS region in memory and set the launch
	//		state of the VMCS to "clear". This action also invalidates the
	//		working-VMCS pointer register to FFFFFFFF_FFFFFFFFH. Software should
	//		verify successful execution of VMCLEAR by checking if RFLAGS.CF = 0
	//		and RFLAGS.ZF = 0.
	__asm
	{
		PUSH	DWORD PTR 0
		PUSH	DWORD PTR PhysicalVMCSRegionPtr.LowPart

		_emit	0x66	// VMCLEAR [ESP]
		_emit	0x0F
		_emit	0xc7
		_emit	0x34
		_emit	0x24

		ADD		ESP, 8
		
		PUSHFD
		POP		eFlags
	}
	if( eFlags.CF != 0 || eFlags.ZF != 0 )
	{
		Log( "ERROR : VMCLEAR operation failed." , 0 );
		goto Abort;
	}
	
	Log( "SUCCESS : VMCLEAR operation completed." , 0 );
	
	//	(4)	Execute the VMPTRLD instruction by supplying the guest-VMCS address.
	//		This initializes the working-VMCS pointer with the new VMCS region抯
	//		physical address.
	__asm
	{
		PUSH	DWORD PTR 0
		PUSH	DWORD PTR PhysicalVMCSRegionPtr.LowPart

		_emit	0x0F	// VMPTRLD [ESP]
		_emit	0xC7
		_emit	0x34
		_emit	0x24

		ADD		ESP, 8
	}

	//
	//	***************************************
	//  *                                     *
	//	*	H.1.1 16-Bit Guest-State Fields   *
	//  *                                     *
	//	***************************************
	//
	//			Guest ES selector									00000800H
				__asm	MOV		seg_selector, ES
				Log( "Setting Guest ES Selector" , seg_selector );
				WriteVMCS( 0x00000800, seg_selector );

	//			Guest CS selector									00000802H
				__asm	MOV		seg_selector, CS
				Log( "Setting Guest CS Selector" , seg_selector );
				WriteVMCS( 0x00000802, seg_selector );

	//			Guest SS selector									00000804H
				__asm	MOV		seg_selector, SS
				Log( "Setting Guest SS Selector" , seg_selector );
				WriteVMCS( 0x00000804, seg_selector );

	//			Guest DS selector									00000806H
				__asm	MOV		seg_selector, DS
				Log( "Setting Guest DS Selector" , seg_selector );
				WriteVMCS( 0x00000806, seg_selector );

	//			Guest FS selector									00000808H
				__asm	MOV		seg_selector, FS
				Log( "Setting Guest FS Selector" , seg_selector );
				WriteVMCS( 0x00000808, seg_selector );

	//			Guest GS selector									0000080AH
				__asm	MOV		seg_selector, GS
				Log( "Setting Guest GS Selector" , seg_selector );
				WriteVMCS( 0x0000080A, seg_selector );

	//			Guest TR selector									0000080EH
				__asm	STR		seg_selector
				ClearBit( &seg_selector, 2 );						// TI Flag
				Log( "Setting Guest TR Selector" , seg_selector );
				WriteVMCS( 0x0000080E, seg_selector );

	//	**************************************
	//  *                                    *
	//	*	H.1.2 16-Bit Host-State Fields   *
	//  *                                    *
	//	**************************************
	//
	//			Host ES selector									00000C00H
				__asm	MOV		seg_selector, ES
				seg_selector &= 0xFFFC;
				Log( "Setting Host ES Selector" , seg_selector );
				WriteVMCS( 0x00000C00, seg_selector );

	//			Host CS selector									00000C02H
				__asm	MOV		seg_selector, CS
				Log( "Setting Host CS Selector" , seg_selector );
				WriteVMCS( 0x00000C02, seg_selector );

	//			Host SS selector									00000C04H
				__asm	MOV		seg_selector, SS
				Log( "Setting Host SS Selector" , seg_selector );
				WriteVMCS( 0x00000C04, seg_selector );

	//			Host DS selector									00000C06H
				__asm	MOV		seg_selector, DS
				seg_selector &= 0xFFFC;
				Log( "Setting Host DS Selector" , seg_selector );
				WriteVMCS( 0x00000C06, seg_selector );

	//			Host FS selector									00000C08H
				__asm	MOV		seg_selector, FS
				Log( "Setting Host FS Selector" , seg_selector );
				WriteVMCS( 0x00000C08, seg_selector );

	//			Host GS selector									00000C0AH
				__asm	MOV		seg_selector, GS
				seg_selector &= 0xFFFC;
				Log( "Setting Host GS Selector" , seg_selector );
				WriteVMCS( 0x00000C0A, seg_selector );

	//			Host TR selector									00000C0CH
				__asm	STR		seg_selector
				Log( "Setting Host TR Selector" , seg_selector );
				WriteVMCS( 0x00000C0C, seg_selector );

	//	***************************************
	//  *                                     *
	//	*	H.2.2 64-Bit Guest-State Fields   *
	//  *                                     *
	//	***************************************
	//
	//			VMCS Link Pointer (full)							00002800H
				temp32 = 0xFFFFFFFF;
				Log( "Setting VMCS Link Pointer (full)" , temp32 );
				WriteVMCS( 0x00002800, temp32 );

	//			VMCS link pointer (high)							00002801H
				temp32 = 0xFFFFFFFF;
				Log( "Setting VMCS Link Pointer (high)" , temp32 );
				WriteVMCS( 0x00002801, temp32 );

	//			Reserved Bits of IA32_DEBUGCTL MSR must be 0
	//			(1D9H)
				ReadMSR( 0x000001D9 );
				Log( "IA32_DEBUGCTL MSR" , msr.Lo );

	//			Guest IA32_DEBUGCTL (full)							00002802H
				temp32 = msr.Lo;
				Log( "Setting Guest IA32_DEBUGCTL (full)" , temp32 );
				WriteVMCS( 0x00002802, temp32 );

	//			Guest IA32_DEBUGCTL (high)							00002803H
				temp32 = msr.Hi;
				Log( "Setting Guest IA32_DEBUGCTL (high)" , temp32 );
				WriteVMCS( 0x00002803, temp32 );

	//	***********************************
	//  *                                 *
	//	*	H.3.1 32-Bit Control Fields   *
	//  *                                 *
	//	***********************************
	//
	//			Pin-based VM-execution controls						00004000H
	//			IA32_VMX_PINBASED_CTLS MSR (index 481H)
				ReadMSR( 0x481 );
					Log( "Pin-based allowed-0" , msr.Lo );
					Log( "Pin-based allowed-1" , msr.Hi );
				temp32 = 0;
				temp32 |= msr.Lo;
				temp32 &= msr.Hi;
				//SetBit( &temp32, 3 );
				Log( "Setting Pin-Based Controls Mask" , temp32 );
				WriteVMCS( 0x00004000, temp32 );

	//			Primary processor-based VM-execution controls		00004002H
	//			IA32_VMX_PROCBASED_CTLS MSR (index 482H)
				ReadMSR( 0x482 );
					Log( "Proc-based allowed-0" , msr.Lo );
					Log( "Proc-based allowed-1" , msr.Hi );
				temp32 = 0;
				temp32 |= msr.Lo;
				temp32 &= msr.Hi;
				Log( "Setting Pri Proc-Based Controls Mask" , temp32 );
				WriteVMCS( 0x00004002, temp32 );

	//			Exception bitmap									00004004H
				temp32 = 0x00000000;
				//SetBit( &temp32, 14 );							// Page Fault
				//SetBit( &temp32, 3 );							// Software Interrupt (INT 3)
				//SetBit( &temp32, 7 );							// No Math Co-Processor
				//SetBit( &temp32, 8 );							// Doudle Fault
				Log( "Exception Bitmap" , temp32 );
				WriteVMCS( 0x00004004, temp32 );
	
	//			Page-fault error-code mask							00004006H
				Log( "Page-Fault Error-Code Mask" , 0 );
				WriteVMCS( 0x00004006, 0 );
	
	//			Page-fault error-code match							00004008H
				Log( "Page-Fault Error-Code Match" , 0 );
				WriteVMCS( 0x00004008, 0 );
	
	//	Get the CR3-target count, MSR store/load counts, et cetera
	//
	//	IA32_VMX_MISC MSR (index 485H)
	ReadMSR( 0x485 );
		Log( "Misc Data" , msr.Lo );
		//Log( "Misc Data" , msr.Hi );
	RtlCopyBytes( &misc_data, &msr.Lo, 4 );
		Log( "   ActivityStates" , misc_data.ActivityStates );
		Log( "   CR3Targets" , misc_data.CR3Targets );
		Log( "   MaxMSRs" , misc_data.MaxMSRs );

	//			VM-exit controls									0000400CH
	//			IA32_VMX_EXIT_CTLS MSR (index 483H)
				ReadMSR( 0x483 );
					Log( "Exit controls allowed-0" , msr.Lo );
					Log( "Exit controls allowed-1" , msr.Hi );
				temp32 = 0;
				temp32 |= msr.Lo;
				temp32 &= msr.Hi;
				SetBit( &temp32, 15 );								// Acknowledge Interrupt On Exit
				Log( "Setting VM-Exit Controls Mask" , temp32 );
				WriteVMCS( 0x0000400C, temp32 );

	//			VM-entry controls									00004012H
	//			IA32_VMX_ENTRY_CTLS MSR (index 484H)
				ReadMSR( 0x484 );
					Log( "VMX Entry allowed-0" , msr.Lo );
					Log( "VMX Entry allowed-1" , msr.Hi );
				temp32 = 0;
				temp32 |= msr.Lo;
				temp32 &= msr.Hi;
				ClearBit( &temp32 , 9 );							// IA-32e Mode Guest Disable
				Log( "Setting VM-Entry Controls Mask" , temp32 );
				WriteVMCS( 0x00004012, temp32 );
	
	//	***************************************
	//  *                                     *
	//	*	H.3.3 32-Bit Guest-State Fields   *
	//  *                                     *
	//	***************************************
	//
	//			Guest ES limit										00004800H
				__asm	MOV seg_selector, ES
				temp32 = 0;
				temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
				Log( "Setting Guest ES limit" , 0xFFFFFFFF );
				WriteVMCS( 0x00004800, 0xFFFFFFFF );

	//			Guest CS limit										00004802H
				__asm	MOV seg_selector, CS
				temp32 = 0;
				temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
				Log( "Setting Guest CS limit" , 0xFFFFFFFF );
				WriteVMCS( 0x00004802, 0xFFFFFFFF );

	//			Guest SS limit										00004804H
				__asm	MOV seg_selector, SS
				temp32 = 0;
				temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
				Log( "Setting Guest SS limit" , 0xFFFFFFFF );
				WriteVMCS( 0x00004804, 0xFFFFFFFF );

	//			Guest DS limit										00004806H
				__asm	MOV seg_selector, DS
				temp32 = 0;
				temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
				Log( "Setting Guest DS limit" , 0xFFFFFFFF );
				WriteVMCS( 0x00004806, 0xFFFFFFFF );

	//			Guest FS limit										00004808H
				__asm	MOV seg_selector, FS
				temp32 = 0;
				temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
				Log( "Setting Guest FS limit" , 0x00001000 );
				WriteVMCS( 0x00004808, 0x00001000 );

	//			Guest GS limit										0000480AH
				__asm	MOV seg_selector, GS
				temp32 = 0;
				temp32 = GetSegmentDescriptorLimit( gdt_base, seg_selector );
				Log( "Setting Guest GS limit" , 0xFFFFFFFF );
				WriteVMCS( 0x0000480A, 0xFFFFFFFF );

	//			Guest TR limit										0000480EH
				__asm
				{
					PUSH	EAX
					
					STR		AX
					MOV		mLDT, AX

					POP		EAX
				}
				temp32 = 0;
				temp32 = GetSegmentDescriptorLimit( gdt_base, mLDT );
				Log( "Setting Guest TR limit" , temp32 );
				WriteVMCS( 0x0000480E, temp32 );

	//			Guest GDTR limit									00004810H
				Log( "Setting Guest GDTR limit" , gdt_reg.Limit );
				WriteVMCS( 0x00004810, gdt_reg.Limit );

	//			Guest IDTR limit									00004812H
				Log( "Setting Guest IDTR limit" , idt_reg.Limit );
				WriteVMCS( 0x00004812, idt_reg.Limit );

				__asm	MOV		seg_selector, CS
				temp32 = seg_selector;
				temp32 >>= 3;
				temp32 *= 8;
				temp32 += (gdt_base + 5);			// CS Segment Descriptor
				__asm
				{
					PUSHAD
					MOV		EAX, temp32
					MOV		EBX, [EAX]
					MOV		temp32, EBX
					POPAD
				}
				temp32 &= 0x0000F0FF;
				Log( "Setting Guest CS access rights" , temp32 );
				WriteVMCS( 0x00004816, temp32 );

				__asm	MOV		seg_selector, DS
				temp32 = seg_selector;
				temp32 >>= 3;
				temp32 *= 8;
				temp32 += (gdt_base + 5);			// DS Segment Descriptor
				__asm
				{
					PUSHAD
					MOV		EAX, temp32
					MOV		EBX, [EAX]
					MOV		temp32, EBX
					POPAD
				}
				temp32 &= 0x0000F0FF;
				Log( "Setting Guest DS access rights" , temp32 );
				WriteVMCS( 0x0000481A, temp32 );

				__asm	MOV		seg_selector, ES
				temp32 = seg_selector;
				temp32 >>= 3;
				temp32 *= 8;
				temp32 += (gdt_base + 5);			// ES Segment Descriptor
				__asm
				{
					PUSHAD
					MOV		EAX, temp32
					MOV		EBX, [EAX]
					MOV		temp32, EBX
					POPAD
				}
				temp32 &= 0x0000F0FF;
				Log( "Setting Guest ES access rights" , temp32 );
				WriteVMCS( 0x00004814, temp32 );

				__asm	MOV		seg_selector, FS
				temp32 = seg_selector;
				temp32 >>= 3;
				temp32 *= 8;
				temp32 += (gdt_base + 5);			// FS Segment Descriptor
				__asm
				{
					PUSHAD
					MOV		EAX, temp32
					MOV		EBX, [EAX]
					MOV		temp32, EBX
					POPAD
				}
				temp32 &= 0x0000F0FF;
				temp32 &= 0xFFFF7FFF;				// Granularity Bit = 0
				Log( "Setting Guest FS access rights" , temp32 );
				WriteVMCS( 0x0000481C, temp32 );

				__asm	MOV		seg_selector, GS
				temp32 = seg_selector;
				temp32 >>= 3;
				temp32 *= 8;
				temp32 += (gdt_base + 5);			// GS Segment Descriptor
				__asm
				{
					PUSHAD
					MOV		EAX, temp32
					MOV		EBX, [EAX]
					MOV		temp32, EBX
					POPAD
				}
				temp32 &= 0x0000F0FF;
				SetBit( &temp32, 16 );				// Unusable
				Log( "Setting Guest GS access rights" , temp32 );
				WriteVMCS( 0x0000481E, temp32 );

				__asm	MOV		seg_selector, SS
				temp32 = seg_selector;
				temp32 >>= 3;
				temp32 *= 8;
				temp32 += (gdt_base + 5);			// SS Segment Descriptor
				__asm
				{
					PUSHAD
					MOV		EAX, temp32
					MOV		EBX, [EAX]
					MOV		temp32, EBX
					POPAD
				}
				temp32 &= 0x0000F0FF;
				Log( "Setting Guest SS access rights" , temp32 );
				WriteVMCS( 0x00004818, temp32 );

				__asm	STR		seg_selector
				temp32 = seg_selector;
				temp32 >>= 3;
				temp32 *= 8;
				temp32 += (gdt_base + 5);			// TR Segment Descriptor
				__asm
				{
					PUSHAD
					MOV		EAX, temp32
					MOV		EBX, [EAX]
					MOV		temp32, EBX
					POPAD
				}
				temp32 &= 0x0000F0FF;
				Log( "Setting Guest TR access rights" , temp32 );
				WriteVMCS( 0x00004822, temp32 );

	//			Guest LDTR access rights							00004820H
				temp32 = 0;
				SetBit( &temp32, 16 );			// Unusable
				Log( "Setting Guest LDTR access rights" , temp32 );
				WriteVMCS( 0x00004820, temp32 );

	//			Guest IA32_SYSENTER_CS								0000482AH
	//			(174H)
				ReadMSR( 0x174 );
				Log( "Setting Guest IA32_SYSENTER_CS" , (ULONG)msr.Lo );
				WriteVMCS( 0x0000482A, msr.Lo );

	//	**************************************
	//  *                                    *
	//	*	H.3.4 32-Bit Host-State Fields   *
	//  *                                    *
	//	**************************************
	//
	//			Host IA32_SYSENTER_CS								00004C00H
	//			(174H)
				ReadMSR( 0x174 );
				Log( "Setting Host IA32_SYSENTER_CS" , (ULONG)msr.Lo );
				WriteVMCS( 0x00004C00, msr.Lo );

	//	**********************************************
	//  *                                            *
	//	*	H.4.3 Natural-Width Guest-State Fields   *
	//  *                                            *
	//	**********************************************
	//
	//			Guest CR0											00006800H
				__asm
				{
					PUSH	EAX
					MOV		EAX, CR0
					MOV		temp32, EAX
					POP		EAX
				}
				
				ReadMSR( 0x486 );							// IA32_VMX_CR0_FIXED0
				Log( "IA32_VMX_CR0_FIXED0" , msr.Lo );

				ReadMSR( 0x487 );							// IA32_VMX_CR0_FIXED1
				Log( "IA32_VMX_CR0_FIXED1" , msr.Lo );
				
				SetBit( &temp32, 0 );		// PE
				SetBit( &temp32, 5 );		// NE
				SetBit( &temp32, 31 );		// PG
				Log( "Setting Guest CR0" , temp32 );
				WriteVMCS( 0x00006800, temp32 );

	//			Guest CR3											00006802H
				__asm
				{
					PUSH	EAX

					_emit	0x0F	// MOV EAX, CR3
					_emit	0x20
					_emit	0xD8

					MOV		temp32, EAX

					POP		EAX
				}
				Log( "Setting Guest CR3" , temp32 );
				WriteVMCS( 0x00006802, temp32 );

	//			Guest CR4											00006804H
				__asm
				{
					PUSH	EAX

					_emit	0x0F	// MOV EAX, CR4
					_emit	0x20
					_emit	0xE0
					
					MOV		temp32, EAX

					POP		EAX
				}

				ReadMSR( 0x488 );							// IA32_VMX_CR4_FIXED0
				Log( "IA32_VMX_CR4_FIXED0" , msr.Lo );

				ReadMSR( 0x489 );							// IA32_VMX_CR4_FIXED1
				Log( "IA32_VMX_CR4_FIXED1" , msr.Lo );

				SetBit( &temp32, 13 );		// VMXE
				Log( "Setting Guest CR4" , temp32 );
				WriteVMCS( 0x00006804, temp32 );

	//			Guest ES base										00006806H
				__asm	MOV		seg_selector, ES
				temp32 = 0;
				temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
				Log( "Setting Guest ES Base" , temp32 );
				WriteVMCS( 0x00006806, temp32 );

	//			Guest CS base										00006808H
				__asm	MOV		seg_selector, CS
				temp32 = 0;
				temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
				Log( "Setting Guest CS Base" , temp32 );
				WriteVMCS( 0x00006808, temp32 );	

	//			Guest SS base										0000680AH
				__asm	MOV		seg_selector, SS
				temp32 = 0;
				temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
				Log( "Setting Guest SS Base" , temp32 );
				WriteVMCS( 0x0000680A, temp32 );	

	//			Guest DS base										0000680CH
				__asm	MOV		seg_selector, DS
				temp32 = 0;
				temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
				Log( "Setting Guest DS Base" , temp32 );
				WriteVMCS( 0x0000680C, temp32 );	

	//			Guest FS base										0000680EH
				__asm	MOV		seg_selector, FS
				temp32 = 0;
				temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
				Log( "Setting Guest FS Base" , temp32 );
				WriteVMCS( 0x0000680E, temp32 );

	//			Guest TR base										00006814H
				__asm
				{
					PUSH	EAX
					
					STR		AX
					MOV		mLDT, AX

					POP		EAX
				}
				temp32 = 0;
				temp32 = GetSegmentDescriptorBase( gdt_base , mLDT );
				Log( "Setting Guest TR Base" , temp32 );
				WriteVMCS( 0x00006814, temp32 );

	//			Guest GDTR base										00006816H
				__asm
				{
					SGDT	gdt_reg
				}
				temp32 = 0;
				temp32 = gdt_reg.BaseHi;
				temp32 <<= 16;
				temp32 |= gdt_reg.BaseLo;
				Log( "Setting Guest GDTR Base" , temp32 );
				WriteVMCS( 0x00006816, temp32 );

	//			Guest IDTR base										00006818H
				__asm
				{
					SIDT	idt_reg
				}
				temp32 = 0;
				temp32 = idt_reg.BaseHi;
				temp32 <<= 16;
				temp32 |= idt_reg.BaseLo;
				Log( "Setting Guest IDTR Base" , temp32 );
				WriteVMCS( 0x00006818, temp32 );

	//			Guest RFLAGS										00006820H
				__asm
				{
					PUSHAD
						
					PUSHFD
					
					MOV		EAX, 0x00006820

					// VMWRITE	EAX, [ESP]
					_emit	0x0F
					_emit	0x79
					_emit	0x04
					_emit	0x24

					POP		eFlags

					POPAD
				}
				Log( "Guest EFLAGS" , eFlags );

	//			Guest IA32_SYSENTER_ESP								00006824H
	//			MSR (175H)
				ReadMSR( 0x175 );
				Log( "Setting Guest IA32_SYSENTER_ESP" , msr.Lo );
				WriteVMCS( 0x00006824, msr.Lo );

	//			Guest IA32_SYSENTER_EIP								00006826H
	//			MSR (176H)
				ReadMSR( 0x176 );
				Log( "Setting Guest IA32_SYSENTER_EIP" , msr.Lo );
				WriteVMCS( 0x00006826, msr.Lo );

	
	//	*********************************************
	//  *                                           *
	//	*	H.4.4 Natural-Width Host-State Fields   *
	//  *                                           *
	//	*********************************************
	//
	//			Host CR0											00006C00H
				__asm
				{
					PUSH	EAX
					MOV		EAX, CR0
					MOV		temp32, EAX
					POP		EAX
				}
				SetBit( &temp32, 5 );								// Set NE Bit
				Log( "Setting Host CR0" , temp32 );
				WriteVMCS( 0x00006C00, temp32 );

	//			Host CR3											00006C02H
				__asm
				{
					PUSH	EAX

					_emit	0x0F	// MOV EAX, CR3
					_emit	0x20
					_emit	0xD8

					MOV		temp32, EAX

					POP		EAX
				}
				Log( "Setting Host CR3" , temp32 );
				WriteVMCS( 0x00006C02, temp32 );

	//			Host CR4											00006C04H
				__asm
				{
					PUSH	EAX

					_emit	0x0F	// MOV EAX, CR4
					_emit	0x20
					_emit	0xE0
					
					MOV		temp32, EAX

					POP		EAX
				}
				Log( "Setting Host CR4" , temp32 );
				WriteVMCS( 0x00006C04, temp32 );				

	//			Host FS base										00006C06H
				__asm	MOV		seg_selector, FS
				temp32 = 0;
				temp32 = GetSegmentDescriptorBase( gdt_base , seg_selector );
				Log( "Setting Host FS Base" , temp32 );
				WriteVMCS( 0x00006C06, temp32 );
				
	//			Host TR base										00006C0AH
				__asm
				{
					PUSH	EAX
					
					STR		AX
					MOV		mLDT, AX

					POP		EAX
				}
				temp32 = 0;
				temp32 = GetSegmentDescriptorBase( gdt_base , mLDT );
				Log( "Setting Host TR Base" , temp32 );
				WriteVMCS( 0x00006C0A, temp32 );

	//			Host GDTR base										00006C0CH
				__asm
				{
					SGDT	gdt_reg
				}
				temp32 = 0;
				temp32 = gdt_reg.BaseHi;
				temp32 <<= 16;
				temp32 |= gdt_reg.BaseLo;
				Log( "Setting Host GDTR Base" , temp32 );
				WriteVMCS( 0x00006C0C, temp32 );				

	//			Host IDTR base										00006C0EH
				__asm
				{
					SIDT	idt_reg
				}
				temp32 = 0;
				temp32 = idt_reg.BaseHi;
				temp32 <<= 16;
				temp32 |= idt_reg.BaseLo;
				Log( "Setting Host IDTR Base" , temp32 );
				WriteVMCS( 0x00006C0E, temp32 );

	//			Host IA32_SYSENTER_ESP								00006C10H
	//			MSR (175H)
				ReadMSR( 0x175 );
				Log( "Setting Host IA32_SYSENTER_ESP" , msr.Lo );
				WriteVMCS( 0x00006C10, msr.Lo );

	//			Host IA32_SYSENTER_EIP								00006C12H
	//			MSR (176H)
				ReadMSR( 0x176 );
				Log( "Setting Host IA32_SYSENTER_EIP" , msr.Lo );
				WriteVMCS( 0x00006C12, msr.Lo );

	//	(5)	Issue a sequence of VMWRITEs to initialize various host-state area
	//		fields in the working VMCS. The initialization sets up the context
	//		and entry-points to the VMM VIRTUAL-MACHINE MONITOR PROGRAMMING
	//		CONSIDERATIONS upon subsequent VM exits from the guest. Host-state
	//		fields include control registers (CR0, CR3 and CR4), selector fields
	//		for the segment registers (CS, SS, DS, ES, FS, GS and TR), and base-
	//		address fields (for FS, GS, TR, GDTR and IDTR; RSP, RIP and the MSRs
	//		that control fast system calls).
	//		

	//	(6)	Use VMWRITEs to set up the various VM-exit control fields, VM-entry
	//		control fields, and VM-execution control fields in the VMCS. Care
	//		should be taken to make sure the settings of individual fields match
	//		the allowed 0 and 1 settings for the respective controls as reported
	//		by the VMX capability MSRs (see Appendix G). Any settings inconsistent
	//		with the settings reported by the capability MSRs will cause VM
	//		entries to fail.
	
	//	(7)	Use VMWRITE to initialize various guest-state area fields in the
	//		working VMCS. This sets up the context and entry-point for guest
	//		execution upon VM entry. Chapter 22 describes the guest-state loading
	//		and checking done by the processor for VM entries to protected and
	//		virtual-8086 guest execution.
	//

	// Clear the VMX Abort Error Code prior to VMLAUNCH
	//
	RtlZeroMemory( (pVMCSRegion + 4), 4 );
	Log( "Clearing VMX Abort Error Code" , *(pVMCSRegion + 4) );

	//	Set EIP, ESP for the Guest right before calling VMLAUNCH
	//
	Log( "Setting Guest ESP" , GuestStack );
	WriteVMCS( 0x0000681C, (ULONG)GuestStack );
	
	Log( "Setting Guest EIP" , GuestReturn );
	WriteVMCS( 0x0000681E, (ULONG)GuestReturn );

	/*
	//	Allocate some stack space for the VMEntry and VMMHandler.
	//
	HighestAcceptableAddress.QuadPart = 0xFFFFFFFF;
	FakeStack = MmAllocateContiguousMemory( 0x2000, HighestAcceptableAddress );
	Log( "FakeStack" , FakeStack );
	*/

	//	Set EIP, ESP for the Host right before calling VMLAUNCH
	//
	Log( "Setting Host ESP" , ((ULONG)FakeStack + 0x1FFF) );
	WriteVMCS( 0x00006C14, ((ULONG)FakeStack + 0x1FFF) );

	Log( "Setting Host EIP" , VMMEntryPoint );
	WriteVMCS( 0x00006C16, (ULONG)VMMEntryPoint );

	////////////////
	//            //
	//	VMLAUNCH  //
	//            //
	////////////////
	__asm
	{
		_emit	0x0F	// VMLAUNCH
		_emit	0x01
		_emit	0xC2
	}
	
	//如果成功，就不会到这里了！
	__asm
	{
		PUSHFD
		POP		eFlags
	}

	Log( "VMLAUNCH Failure" , 0xDEADF00D )
	
	if( eFlags.CF != 0 || eFlags.ZF != 0 || TRUE )
	{
		//
		//	Get the ERROR number using VMCS field 00004400H
		//
		__asm
		{
			PUSHAD
			
			MOV		EAX, 0x00004400
			
			_emit	0x0F	// VMREAD  EBX, EAX
			_emit	0x78
			_emit	0xC3
			
			MOV		ErrorCode, EBX
			
			POPAD
		}
		
		Log( "VM Instruction Error" , ErrorCode );
	}

Abort:

	ScrubTheLaunch = 1;
	__asm
	{
		MOV		ESP, GuestStack
		JMP		GuestReturn
	}
}

////////////////////
//                //
//  DriverUnload  //
//                //
////////////////////
VOID DriverUnload( IN PDRIVER_OBJECT DriverObject )
{
	ULONG		ExitEFlags = 0;

	ULONG		ExitEAX = 0;
	ULONG		ExitECX = 0;
	ULONG		ExitEDX = 0;
	ULONG		ExitEBX = 0;
	ULONG		ExitESP = 0;
	ULONG		ExitEBP = 0;
	ULONG		ExitESI = 0;
	ULONG		ExitEDI = 0;
	
	DbgPrint( "[vmm-unload] Active Processor Bitmap  [%08X]\n", (ULONG)KeQueryActiveProcessors( ) );
	
	DbgPrint( "[vmm-unload] Disabling VMX mode on CPU 0.\n" );
	KeSetSystemAffinityThread( (KAFFINITY) 0x00000001 );

	if( VMXIsActive )
	{
		__asm
		{
			PUSHAD
			MOV		EAX, 0x12345678
			
			_emit 0x0F		// VMCALL
			_emit 0x01
			_emit 0xC1
			
			POPAD
		}
	}
	
	DbgPrint( "[vmm-unload] Freeing memory regions.\n" );
	
	MmFreeNonCachedMemory( pVMXONRegion , 4096 );
	MmFreeNonCachedMemory( pVMCSRegion , 4096 );
	ExFreePoolWithTag( FakeStack, 'kSkF' );
	
	DbgPrint( "[vmm-unload] Driver Unloaded.\n");
}

////////////////////
//                //
//  Driver Entry  //
//                //
////////////////////
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
	NTSTATUS	ntStatus = STATUS_UNSUCCESSFUL;
	
	ULONG		EntryEFlags = 0;
	ULONG		cr4 = 0;

	ULONG		EntryEAX = 0;
	ULONG		EntryECX = 0;
	ULONG		EntryEDX = 0;
	ULONG		EntryEBX = 0;
	ULONG		EntryESP = 0;
	ULONG		EntryEBP = 0;
	ULONG		EntryESI = 0;
	ULONG		EntryEDI = 0;
	
	DriverObject->DriverUnload = DriverUnload;
	
	Log( "Driver Routines" , 0 );
	Log( "---------------" , 0 );
	Log( "   Driver Entry", DriverEntry );
	Log( "   Driver Unload", DriverUnload );
	Log( "   StartVMX", StartVMX );
	Log( "   VMMEntryPoint", VMMEntryPoint );
	
	//	Check if PAE is enabled.
	//PAE（Physical Address Extension）物理地址扩展，PAE=1时，页物理地址可以扩展到36bi s以上，PAE=0时只能用32bits的物理地址
	__asm
	{
		PUSH	EAX

		_emit	0x0F	// MOV	EAX, CR4
		_emit	0x20
		_emit	0xE0
		
		MOV		cr4, EAX

		POP		EAX
	}
	if( cr4 & 0x00000020 )//检查ＰＡＥ位，即第五位，如果是１，则返回
	{
		Log( "******************************" , 0 );
		Log( "Error : PAE must be disabled." , 0 );
		Log( "Add the following to boot.ini:" , 0 );
		Log( "  /noexecute=alwaysoff /nopae" , 0 );
		Log( "******************************" , 0 );
		return STATUS_UNSUCCESSFUL;
	}
	
	//	Allocate the VMXON region memory.
	//
	pVMXONRegion = MmAllocateNonCachedMemory( 4096 );//为VMXON分配大小为4096字节，4KB的一个空间；
	if( pVMXONRegion == NULL )
	{
		Log( "ERROR : Allocating VMXON Region memory." , 0 );
		return STATUS_UNSUCCESSFUL;
	}
	Log( "VMXONRegion virtual address" , pVMXONRegion );
	RtlZeroMemory( pVMXONRegion, 4096 );//对分配的内存空间进行初始化，必须的
	PhysicalVMXONRegionPtr = MmGetPhysicalAddress( pVMXONRegion );//得到分配到的空间的物理地址
	Log( "VMXONRegion physical address" , PhysicalVMXONRegionPtr.LowPart );
	
	//	Allocate the VMCS region memory.
	//
	pVMCSRegion = MmAllocateNonCachedMemory( 4096 );//为VMCS分配大小为4096字节，4KB的一个空间；
	if( pVMCSRegion == NULL )
	{
		Log( "ERROR : Allocating VMCS Region memory." , 0 );
		MmFreeNonCachedMemory( pVMXONRegion , 4096 );
		return STATUS_UNSUCCESSFUL;
	}
	Log( "VMCSRegion virtual address" , pVMCSRegion );
	RtlZeroMemory( pVMCSRegion, 4096 );
	PhysicalVMCSRegionPtr = MmGetPhysicalAddress( pVMCSRegion );
	Log( "VMCSRegion physical address" , PhysicalVMCSRegionPtr.LowPart );
	
	//	Allocate stack for the VM Exit Handler.
	//
	FakeStack = ExAllocatePoolWithTag( NonPagedPool , 0x2000, 'kSkF' );//在内核堆中分配2000字节的空间
	if( FakeStack == NULL )
	{
		Log( "ERROR : Allocating VM Exit Handler stack memory." , 0 );
		MmFreeNonCachedMemory( pVMXONRegion , 4096 );
		MmFreeNonCachedMemory( pVMCSRegion , 4096 );
		return STATUS_UNSUCCESSFUL;
	}
	Log( "FakeStack" , FakeStack );
	
	
	//	Save the state of the architecture.
	//
	__asm
	{
		CLI
		MOV		GuestStack, ESP//把原来系统栈的栈顶指针保存在GuestStack中
	}
	
	__asm
	{
		PUSHAD    
		POP		EntryEDI
		POP		EntryESI
		POP		EntryEBP
		POP		EntryESP
		POP		EntryEBX
		POP		EntryEDX
		POP		EntryECX
		POP		EntryEAX
		PUSHFD 
		POP		EntryEFlags
	}
	
	StartVMX( );
	
	//	Restore the state of the architecture.
	//
	__asm
	{
		PUSH	EntryEFlags
		POPFD
		PUSH	EntryEAX
		PUSH	EntryECX
		PUSH	EntryEDX
		PUSH	EntryEBX
		PUSH	EntryESP
		PUSH	EntryEBP
		PUSH	EntryESI
		PUSH	EntryEDI
		POPAD
	}
	
	__asm
	{
		STI
		MOV		ESP, GuestStack
	}
	
	Log( "Running on Processor" , KeGetCurrentProcessorNumber() );
	
	if( ScrubTheLaunch == 1 )
	{
		Log( "ERROR : Launch aborted." , 0 );
		MmFreeNonCachedMemory( pVMXONRegion , 4096 );
		MmFreeNonCachedMemory( pVMCSRegion , 4096 );
		ExFreePoolWithTag( FakeStack, 'kSkF' );
		return STATUS_UNSUCCESSFUL;
	}
	
	Log( "VM is now executing." , 0 );
	
	return STATUS_SUCCESS;
}

ULONG		ExitReason;
ULONG		ExitQualification;
ULONG		ExitInterruptionInformation;
ULONG		ExitInterruptionErrorCode;
ULONG		IDTVectoringInformationField;
ULONG		IDTVectoringErrorCode;
ULONG		ExitInstructionLength;
ULONG		ExitInstructionInformation;

ULONG		GuestEIP;
ULONG		GuestResumeEIP;
ULONG		GuestESP;
ULONG		GuestCS;
ULONG		GuestCR0;
ULONG		GuestCR3;
ULONG		GuestCR4;
ULONG		GuestEFLAGS;

ULONG		GuestEAX;
ULONG		GuestEBX;
ULONG		GuestECX;
ULONG		GuestEDX;
ULONG		GuestEDI;
ULONG		GuestESI;
ULONG		GuestEBP;

ULONG		movcrControlRegister;
ULONG		movcrAccessType;
ULONG		movcrOperandType;
ULONG		movcrGeneralPurposeRegister;
ULONG		movcrLMSWSourceData;

///////////////////////
//                   //
//  VMM Entry Point  //
//                   //
///////////////////////
__declspec( naked ) VOID VMMEntryPoint( )
{
	__asm	CLI
	
	__asm	PUSHAD

	//
	//	Record the General-Purpose registers.
	//
	__asm	MOV GuestEAX, EAX
	__asm	MOV GuestEBX, EBX
	__asm	MOV GuestECX, ECX
	__asm	MOV GuestEDX, EDX
	__asm	MOV GuestEDI, EDI
	__asm	MOV GuestESI, ESI
	__asm	MOV GuestEBP, EBP
	
	///////////////////
	//               //
	//  Exit Reason  //		0x00004400
	//               //
	///////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00004402
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		ExitReason, EBX
		
		POPAD
	}
	
	if( ExitReason == 0x0000000A ||	// CPUID
		ExitReason == 0x00000012 || // VMCALL
		ExitReason == 0x0000001C || // MOV CR
		ExitReason == 0x0000001F || // RDMSR
		ExitReason == 0x00000020 ||	// WRMSR
		( ExitReason > 0x00000012 && ExitReason < 0x0000001C ) )
	{
		HandlerLogging = 0;
	}
	else
	{
		HandlerLogging = 1;
	}
	
	if( HandlerLogging )
	{
		Log( "----- VMM Handler CPU0 -----", 0 );
		Log( "Guest EAX" , GuestEAX );
		Log( "Guest EBX" , GuestEBX );
		Log( "Guest ECX" , GuestECX );
		Log( "Guest EDX" , GuestEDX );
		Log( "Guest EDI" , GuestEDI );
		Log( "Guest ESI" , GuestESI );
		Log( "Guest EBP" , GuestEBP );
		Log( "Exit Reason" , ExitReason );
	}

	//////////////////////////
	//                      //
	//  Exit Qualification  //	00006400H
	//                      //
	//////////////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00006400
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		ExitQualification, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "Exit Qualification" , ExitQualification );

	////////////////////////////////////////
	//                                    //
	//  VM-Exit Interruption Information  //	00004404H
	//                                    //
	////////////////////////////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00004404
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		ExitInterruptionInformation, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "Exit Interruption Information" , ExitInterruptionInformation );

	///////////////////////////////////////
	//                                   //
	//  VM-Exit Interruption Error Code  //	00004406H
	//                                   //
	///////////////////////////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00004406
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		ExitInterruptionErrorCode, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "Exit Interruption Error Code" , ExitInterruptionErrorCode );

	///////////////////////////////////////
	//                                   //
	//  IDT-Vectoring Information Field  //	00004408H
	//                                   //
	///////////////////////////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00004408
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		IDTVectoringInformationField, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "IDT-Vectoring Information Field" , IDTVectoringInformationField );

	////////////////////////////////
	//                            //
	//  IDT-Vectoring Error Code  //	0000440AH
	//                            //
	////////////////////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x0000440A
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		IDTVectoringErrorCode, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "IDT-Vectoring Error Code" , IDTVectoringErrorCode );

	//////////////////////////////////
	//                              //
	//  VM-Exit Instruction Length  //	0000440CH
	//                              //
	//////////////////////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x0000440C
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		ExitInstructionLength, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM-Exit Instruction Length" , ExitInstructionLength );

	///////////////////////////////////////
	//                                   //
	//  VM-Exit Instruction Information  //	0000440EH
	//                                   //
	///////////////////////////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x0000440E
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		ExitInstructionInformation, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM-Exit Instruction Information" , ExitInstructionInformation );

	/////////////////
	//             //
	//  Guest EIP  //
	//             //
	/////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x0000681E
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		GuestEIP, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM Exit EIP" , GuestEIP );

	//
	//	Writing the Guest VMCS EIP uses general registers.
	//	Must complete this before setting general registers
	//	for guest return state.
	//
	GuestResumeEIP = GuestEIP + ExitInstructionLength;
	WriteVMCS( 0x0000681E, (ULONG)GuestResumeEIP );

	/////////////////
	//             //
	//  Guest ESP  //
	//             //
	/////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x0000681C
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		GuestESP, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM Exit ESP" , GuestESP );

	////////////////
	//            //
	//  Guest CS  //
	//            //
	////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00000802
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		GuestCS, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM Exit CS" , GuestCS );

	/////////////////
	//             //
	//  Guest CR0  //
	//             //
	/////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00006800
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		GuestCR0, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM Exit CR0" , GuestCR0 );

	/////////////////
	//             //
	//  Guest CR3  //
	//             //
	/////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00006802
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		GuestCR3, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM Exit CR3" , GuestCR3 );

	/////////////////
	//             //
	//  Guest CR4  //
	//             //
	/////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00006804
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		GuestCR4, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM Exit CR4" , GuestCR4 );

	////////////////////
	//                //
	//  Guest EFLAGS  //
	//                //
	////////////////////
	__asm
	{
		PUSHAD
		
		MOV		EAX, 0x00006820
		
		_emit	0x0F	// VMREAD  EBX, EAX
		_emit	0x78
		_emit	0xC3
		
		MOV		GuestEFLAGS, EBX
		
		POPAD
	}
	if( HandlerLogging ) Log( "VM Exit EFLAGS" , GuestEFLAGS );

	/////////////////////////////////////////////
	//                                         //
	//  *** EXIT REASON CHECKS START HERE ***  //
	//                                         //
	/////////////////////////////////////////////

	/////////////////////////////////////////////////////////////////////////////////////
	//                                                                                 //
	//  VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMREAD, VMWRITE, VMRESUME, VMXOFF, VMXON  //
	//                                                                                 //
	/////////////////////////////////////////////////////////////////////////////////////
	if( ExitReason > 0x00000012 && ExitReason < 0x0000001C )
	{
		Log( "Request has been denied - CPU0", ExitReason );

		__asm
		{
			POPAD
			JMP		Resume
		}
	}
	
	//////////////
	//          //
	//  VMCALL  //
	//          //
	//////////////
	if( ExitReason == 0x00000012 )
	{
		Log( "VMCALL detected - CPU0" , 0 );

		if( GuestEAX == 0x12345678 )
		{
			//	Switch off VMX mode.
			//
			Log( "- Terminating VMX Mode.", 0xDEADDEAD );
			__asm
			{
				_emit	0x0F	// VMXOFF
				_emit	0x01
				_emit	0xC4
			}
			
			Log( "- Flow Control Return to Address" , GuestResumeEIP );
			
			__asm
			{
				POPAD
				MOV	ESP, GuestESP
				STI
				JMP	GuestResumeEIP
			}
		}

		Log( "- Request has been denied." , ExitReason );
		
		__asm
		{
			POPAD
			JMP	Resume
		}
	}

	////////////
	//        //
	//  INVD  //
	//        //
	////////////
	if( ExitReason == 0x0000000D )
	{
		Log( "INVD detected - CPU0" , 0 );

		__asm
		{
			_emit 0x0F
			_emit 0x08

			POPAD
			JMP		Resume
		}
	}
	
	/////////////
	//         //
	//  RDMSR  //
	//         //
	/////////////
	if( ExitReason == 0x0000001F )
	{
		Log( "Read MSR - CPU0" , GuestECX );
		__asm
		{
			POPAD
			
			MOV		ECX, GuestECX

			_emit	0x0F
			_emit	0x32
			
			JMP		Resume
		}
	}
	
	/////////////
	//         //
	//  WRMSR  //
	//         //
	/////////////
	if( ExitReason == 0x00000020 )
	{
		Log( "Write MSR - CPU0" , GuestECX );
		__asm
		{
			POPAD
			
			MOV		ECX, GuestECX
			MOV		EAX, GuestEAX
			MOV		EDX, GuestEDX

			_emit	0x0F
			_emit	0x30
			
			JMP		Resume
		}
	}
	
	/////////////
	//         //
	//  CPUID  //
	//         //
	/////////////
	if( ExitReason == 0x0000000A )
	{
		if( HandlerLogging )
		{
			Log( "CPUID detected - CPU0", 0 );
			Log( "- EAX", GuestEAX );
		}
		
		if( GuestEAX == 0x00000000 )
		{
			__asm
			{
				POPAD
				
				MOV		EAX, 0x00000000
				
				CPUID
				
				MOV		EBX, 0x61656C43
				MOV		ECX, 0x2E636E6C
				MOV		EDX, 0x74614872

				JMP		Resume
			}
		}
		
		__asm
		{
			POPAD
			
			MOV		EAX, GuestEAX
			
			CPUID

			JMP		Resume
		}
	}

	///////////////////////////////
	//                           //
	//  Control Register Access  //
	//                           //
	///////////////////////////////
	if( ExitReason == 0x0000001C )
	{
		if( HandlerLogging ) Log( "Control Register Access detected.", 0 );

		movcrControlRegister = ( ExitQualification & 0x0000000F );
		movcrAccessType = ( ( ExitQualification & 0x00000030 ) >> 4 );
		movcrOperandType = ( ( ExitQualification & 0x00000040 ) >> 6 );
		movcrGeneralPurposeRegister = ( ( ExitQualification & 0x00000F00 ) >> 8 );
		
		if( HandlerLogging )
		{
			Log( "- movcrControlRegister", movcrControlRegister );
			Log( "- movcrAccessType", movcrAccessType );
			Log( "- movcrOperandType", movcrOperandType );
			Log( "- movcrGeneralPurposeRegister", movcrGeneralPurposeRegister );
		}

		//	Control Register Access (CR3 <-- reg32)
		//
		if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0 )
		{
			WriteVMCS( 0x00006802, GuestEAX );
			__asm POPAD
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1 )
		{
			WriteVMCS( 0x00006802, GuestECX );
			__asm POPAD
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2 )
		{
			WriteVMCS( 0x00006802, GuestEDX );
			__asm POPAD
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3 )
		{
			WriteVMCS( 0x00006802, GuestEBX );
			__asm POPAD
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4 )
		{
			WriteVMCS( 0x00006802, GuestESP );
			__asm POPAD
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5 )
		{
			WriteVMCS( 0x00006802, GuestEBP );
			__asm POPAD
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6 )
		{
			WriteVMCS( 0x00006802, GuestESI );
			__asm POPAD
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7 )
		{
			WriteVMCS( 0x00006802, GuestEDI );
			__asm POPAD
			goto Resume;
		}
		//	Control Register Access (reg32 <-- CR3)
		//
		if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0 )
		{
			__asm	POPAD
			__asm	MOV EAX, GuestCR3
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1 )
		{
			__asm	POPAD
			__asm	MOV ECX, GuestCR3
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2 )
		{
			__asm	POPAD
			__asm	MOV EDX, GuestCR3
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3 )
		{
			__asm	POPAD
			__asm	MOV EBX, GuestCR3
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4 )
		{
			__asm	POPAD
			__asm	MOV ESP, GuestCR3
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5 )
		{
			__asm	POPAD
			__asm	MOV EBP, GuestCR3
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6 )
		{
			__asm	POPAD
			__asm	MOV ESI, GuestCR3
			goto Resume;
		}
		if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7 )
		{
			__asm	POPAD
			__asm	MOV EDI, GuestCR3
			goto Resume;
		}
	}
	
Exit:
	
	//
	//	Switch off VMX mode.
	//
	Log( "Terminating VMX Mode.", 0xDEADDEAD );
	__asm
	{
		_emit	0x0F	// VMXOFF
		_emit	0x01
		_emit	0xC4
	}
	
	VMXIsActive = 0;
	
	Log( "Flow Control Return to Address" , GuestEIP );
	
	__asm
	{
		POPAD
		MOV		ESP, GuestESP
		STI
		JMP		GuestEIP
	}
	
Resume:
	
	//	Need to execute the VMRESUME without having changed
	//	the state of the GPR and ESP et cetera.
	//
	__asm
	{
		STI
		
		_emit	0x0F	// VMRESUME
		_emit	0x01
		_emit	0xC3
	}
}

