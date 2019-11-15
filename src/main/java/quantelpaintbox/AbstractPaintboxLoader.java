package quantelpaintbox;

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractPaintboxLoader extends AbstractLibrarySupportLoader {

	protected VectorTable vectors;

	protected void createPaintboxHardwareSegments(FlatProgramAPI fpa, ByteProvider provider, Program program, TaskMonitor monitor,
			MessageLog log) {
		
		// FIXME unknown
		//createSegment(fpa, null, "XXX_UNK_020000", 0x020000, 0x20000, true, true, true, true, log);
		
		
		// NVRAM
		createSegment(fpa, null, "NVRAM", 0x040000, 0x1000, true, true, true, false, log);
		createNamedArray(fpa, program, 0x040000, "NVRAM", 0x1000, ByteDataType.dataType, log);
		// TODO: mirror segments

		
		// FIXME unknown
		//createSegment(fpa, null, "XXX_UNK_060000", 0x060000, 0x20000, true, true, true, true, log);
		
		
		
		// -- RAM --
		// 0x080000 - unconditional bus error
		//createSegment(fpa, null, "XXX_BUSERR_080000", 0x080000, 0x020000, true, true, true, true, log);
		// 0x100000 - Main RAM -- 32 off MB81400 = 16MiB
		createSegment(fpa, null, "RAM", 0x100000, 0xDE0000, true, true, true, false, log);
		// 0x080000 - unconditional bus error
		//createSegment(fpa, null, "XXX_BUSERR_EE0000", 0xEE0000, 0x020000, true, true, true, true, log);

		
		
		// -- Peripherals --
		
		// Unknown
		//createSegment(fpa, null, "IO_UNK_F00000",	0xF00000, 0x10000,	true, true, false, true, log);
		
		// 68681 Dual UART -
		//   Only the n+1 addresses are used, and only in byte access mode.
		//   This is because the UART is tied to the lower address bus, and 68000 words are big-endian.
		//   To write to the lower byte, we need to do a byte write to addr+1.
		createSegment(fpa, null, "IO_DUART",		0xF10000, 32,		true, true, false, true, log);
		Structure duart = new StructureDataType("DUART", 0);
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "MR1A_MR2A",	"R/W: Mode register A (MR1A, MR2A)");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "SRA_CSRA",		"R: Status Reg A\nW:Clk Sel Reg A");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "BRGT_CRA",		"R: BRG test\nW:Cmd Reg A");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "RHRA_THRA",	"R: Rx Buf A\nW:Tx Buf A");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "IPCR_ACR",		"R: Input port change reg\nW: Aux control reg");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "ISR_IMR",		"R: Interrupt status reg\nW: Interrupt mask reg");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "CTU_CTUR",		"R: MSB of counter in counter mode\nW:C/T upper preset value");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "CTL_CTLR",		"R: MSB of counter in counter mode\nW:C/T upper preset value");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "MR1B_MR2B",	"R/W: Mode Register B (MR1B, MR2B)");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "SRB_CSRB",		"R: Status Reg B\nW:Clk Sel Reg B");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "1XTEST_CRB",	"R: 1x/16x Test\nW: Cmd Reg B");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "RHRB_THRB",	"R: Rx Buf B\nW:Tx Buf B");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "IVR",			"R/W: Interrupt vector register");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "INP_OPCR",		"R: Input ports IP0-IP6\nW: Output Port Config Register");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "START_OBS",	"R: Start Counter command\nW: Set Output Port Bits Command");
		duart.add(Undefined1DataType.dataType, 1);
		duart.add(ByteDataType.dataType, 1, "STOP_OBR",		"R: Stop Counter command\nW: Reset Output Port Bits Command");
		try {
			DataUtilities.createData(program, fpa.toAddr(0xF10000), duart, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			program.getSymbolTable().createLabel(fpa.toAddr(0xF10000), "IO_DUART", SourceType.IMPORTED);
		} catch (CodeUnitInsertionException | InvalidInputException e) {
			log.appendException(e);
		}

		// Diagnostic LED display
		createSegment(fpa, null, "IO_LED",		0xF100F1, 1, true, true, false, true, log);
		createNamedData(fpa, program, 0xF100F1L, "IO_LED_LED", ByteDataType.dataType, log);
		fpa.setEOLComment( fpa.toAddr(0xF100F1L), "Diagnostic LED");

		// MC68901 MFP
		createSegment(fpa, null, "IO_MC68901_MFP",	0xF20000, 0x30, true, true, false, true, log);
		// TODO registers
		
		// MC68450 DMA controller
		createSegment(fpa, null, "IO_MC68450_DMA",	0xF30000, 0x100, true, true, false, true, log);
		// TODO registers
		
		// WD33C93 SCSI controller
		createSegment(fpa, null, "IO_WD33C93A_SCSI",0xF40000, 0x20, true, true, false, true, log);
		// TODO registers
	
		
		/// FIXME big ol' unknown
		
		
		// Rotary switches 
		createSegment(fpa, null, "IO_SWITCHES",		0xFA0000, 0x10000, true, true, false, true, log);
		createNamedData(fpa, program, 0xFA0000L, "IO_ROTARY_SWITCHES", "Rotary switches -- 0x0jkl", WordDataType.dataType, log);
		
		// Security PAL
		createSegment(fpa, null, "IO_SECURITY_PAL",	0xFD0000, 0x10000, true, true, false, true, log);
		createNamedArray(fpa, program, 0xFD0000L, "SECURITY_PAL", 0x10000, ByteDataType.dataType, log);
		fpa.setEOLComment(  fpa.toAddr(0xFD0000L), "Read:  Security PAL");
		
		
		/*
		
		// Peripherals
		createSegment(fpa, null, "IO_ADC",		0x240000, 256, true, true, false, true, log);	// ZN448 A-D converter
		createNamedData(fpa, program, 0x240001L, "IO_ADC_ADC", ByteDataType.dataType, log);
		fpa.setEOLComment( fpa.toAddr(0x240001L), "Read:  ADC result\nWrite: Start conversion");
		
		createSegment(fpa, null, "IO_UNK_01",	0x240100, 256, true, true, false, true, log);
		
		createSegment(fpa, null, "IO_RF_PHASE",	0x240200, 256, true, true, false, true, log);	// RF phase detector
		
		if (false) {
			Structure rfPhase = new StructureDataType("RF_PHASE", 0);
			rfPhase.add(ByteDataType.dataType, "HI", "RF Phase, high nibble (in LSB)");
			rfPhase.add(ByteDataType.dataType, "LO", "RF Phase, low byte");
			try {
				DataUtilities.createData(program, fpa.toAddr(0x240200), rfPhase, -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			} catch (CodeUnitInsertionException e) {
				log.appendException(e);
			}
		} else {
			createNamedData(fpa, program, 0x240200L, "IO_RF_PHASE_HI", ByteDataType.dataType, log);
			fpa.setEOLComment( fpa.toAddr(0x240200L), "Read: RF phase high nibble (Msbyte indeterminate, Lsbyte highword)");
			createNamedData(fpa, program, 0x240201L, "IO_RF_PHASE_LO", ByteDataType.dataType, log);
			fpa.setEOLComment( fpa.toAddr(0x240201L), "Read: RF phase low nibble");
		}
		


		createSegment(fpa, null, "IO_UNK_04",	0x240400, 256, true, true, false, true, log);

		createSegment(fpa, null, "IO_UNK_05",	0x240500, 256, true, true, false, true, log);

		createSegment(fpa, null, "IO_UNK_06",	0x240600, 256, true, true, false, true, log);

		createSegment(fpa, null, "IO_UNK_07",	0x240700, 256, true, true, false, true, log);

		createSegment(fpa, null, "IO_UNK_08",	0x240800, 256, true, true, false, true, log);

		//createSegment(fpa, null, "IO_UNDEFINED",0x240900, 0x250000-0x240900, true, true, false, true, log);		// Undefined, no peripherals assigned

		*/


		/*
		if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Question",
				"Create Sega CD segment?")) {
			if (romStream.available() > 0x3FFFFFL) {
				createSegment(fpa, provider.getInputStream(0x400000L), "EPA", 0x400000L, 0x400000L, true, true, false, false,
						log);
			} else {
				createSegment(fpa, null, "EPA", 0x400000L, 0x400000L, true, true, false, false, log);
			}
		}

		if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Question",
				"Create Sega 32X segment?")) {
			createSegment(fpa, null, "32X", 0x800000L, 0x200000L, true, true, false, false, log);
		}

		createSegment(fpa, null, "Z80", 0xA00000L, 0x10000L, true, true, false, false, log);
		createNamedData(fpa, program, 0xA04000L, "Z80_YM2612", DWordDataType.dataType, log);

		createSegment(fpa, null, "SYS1", 0xA10000L, 16 * 2, true, true, false, true, log);
		createNamedData(fpa, program, 0xA10000L, "IO_PCBVER", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10002L, "IO_CT1_DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10004L, "IO_CT2_DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10006L, "IO_EXT_DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10008L, "IO_CT1_CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1000AL, "IO_CT2_CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1000CL, "IO_EXT_CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1000EL, "IO_CT1_RX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10010L, "IO_CT1_TX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10012L, "IO_CT1_SMODE", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10014L, "IO_CT2_RX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10016L, "IO_CT2_TX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10018L, "IO_CT2_SMODE", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1001AL, "IO_EXT_RX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1001CL, "IO_EXT_TX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1001EL, "IO_EXT_SMODE", WordDataType.dataType, log);

		createSegment(fpa, null, "SYS2", 0xA11000L, 2, true, true, false, true, log);
		createNamedData(fpa, program, 0xA11000L, "IO_RAMMODE", WordDataType.dataType, log);

		createSegment(fpa, null, "Z802", 0xA11100L, 2, true, true, false, true, log);
		createNamedData(fpa, program, 0xA11100L, "IO_Z80BUS", WordDataType.dataType, log);

		createSegment(fpa, null, "Z803", 0xA11200L, 2, true, true, false, true, log);
		createNamedData(fpa, program, 0xA11200L, "IO_Z80RES", WordDataType.dataType, log);

		createSegment(fpa, null, "FDC", 0xA12000L, 0x100, true, true, false, true, log);
		createNamedArray(fpa, program, 0xA12000L, "IO_FDC", 0x100, ByteDataType.dataType, log);

		createSegment(fpa, null, "TIME", 0xA13000L, 0x100, true, true, false, true, log);
		createNamedArray(fpa, program, 0xA13000L, "IO_TIME", 0x100, ByteDataType.dataType, log);

		createSegment(fpa, null, "TMSS", 0xA14000L, 4, true, true, false, true, log);
		createNamedData(fpa, program, 0xA14000L, "IO_TMSS", DWordDataType.dataType, log);

		createSegment(fpa, null, "VDP", 0xC00000L, 2 * 9, true, true, false, true, log);
		createNamedData(fpa, program, 0xC00000L, "VDP_DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00002L, "VDP__DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00004L, "VDP_CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00006L, "VDP__CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00008L, "VDP_CNTR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC0000AL, "VDP__CNTR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC0000CL, "VDP___CNTR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC0000EL, "VDP____CNTR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00011L, "VDP_PSG", ByteDataType.dataType, log);

		createSegment(fpa, null, "RAM", 0xFF0000L, 0x10000L, true, true, true, false, log);
		createMirrorSegment(program.getMemory(), fpa, "RAM", 0xFF0000L, 0xFFFF0000L, 0x10000L, log);
		*/
	}

	/**
	 * Mark the M68000 vector table
	 * 
	 * @param program
	 * @param fpa
	 * @param log
	 */
	protected void markVectorTable(Program program, FlatProgramAPI fpa, MessageLog log) {
		try {
			// Declare the vector table as data
			DataUtilities.createData(program, fpa.toAddr(0), vectors.toDataType(), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

			// Define the vectors as functions (if possible) and mark them as execution entry points
			for (VectorFunc func : vectors.getVectors()) {
				fpa.createFunction(func.getAddress(), func.getName());
				fpa.addEntryPoint(func.getAddress());
			}
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}
	

	/**
	 * Declare an array of data elements (bytes, words or dwords) and assign it a label.
	 * 
	 * @param fpa
	 * @param program
	 * @param address
	 * @param name
	 * @param numElements
	 * @param type
	 * @param log
	 */
	protected void createNamedArray(FlatProgramAPI fpa, Program program, long address, String name, int numElements, DataType type, MessageLog log) {
		try {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type, type.getLength());
			arrayCmd.applyTo(program);
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	/**
	 * Set the type of a data byte, word or DWord, and add it to the symbol table.
	 * 
	 * @param fpa
	 * @param program
	 * @param address
	 * @param name
	 * @param type
	 * @param log
	 */
	protected void createNamedData(FlatProgramAPI fpa, Program program, long address, String name, DataType type, MessageLog log) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(fpa.toAddr(address));
			} else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(fpa.toAddr(address));
			} else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(fpa.toAddr(address));
			}
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	protected void createNamedData(FlatProgramAPI fpa, Program program, long address, String name, String comment, DataType type, MessageLog log) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(fpa.toAddr(address));
			} else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(fpa.toAddr(address));
			} else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(fpa.toAddr(address));
			}
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
			fpa.setEOLComment(fpa.toAddr(address), comment);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	/**
	 * Create a new segment with data from the input stream
	 * 
	 * @param fpa
	 * @param stream
	 * @param name
	 * @param address
	 * @param size
	 * @param read
	 * @param write
	 * @param execute
	 * @param volatil
	 * @param log
	 */
	protected void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size,
			boolean read, boolean write, boolean execute, boolean volatil, MessageLog log) {
		MemoryBlock block = null;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	/**
	 * Create a segment which mirrors data in another address (e.g. IDATA)
	 * 
	 * @param memory
	 * @param fpa
	 * @param name
	 * @param base
	 * @param new_addr
	 * @param size
	 * @param log
	 */
	protected void createMirrorSegment(Memory memory, FlatProgramAPI fpa, String name, long base, long new_addr,
			long size, MessageLog log) {
		MemoryBlock block = null;
		Address baseAddress = fpa.toAddr(base);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(new_addr), baseAddress, size);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead(baseBlock.isRead());
			block.setWrite(baseBlock.isWrite());
			block.setExecute(baseBlock.isExecute());
			block.setVolatile(baseBlock.isVolatile());
		} catch (LockException | MemoryConflictException | AddressOverflowException e) {
			log.appendException(e);
		}
	}

	
	private Boolean isValidSymbolName(String s) {
		final String VALID_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_.";
		final String NUMBERS = "0123456789";
		
		for (char ch : s.toCharArray()) {
			// If the string contains an invalid character, abort
			if (VALID_CHARS.indexOf(ch) == -1) {
				return false;
			}			
		}
		
		// Make sure the first character is not a number
		if (NUMBERS.indexOf(s.charAt(0)) != -1) {
			return false;
		}
		
		return true;
	}

	/**
	 * Extract symbol tables from the image
	 * 
	 * @param provider
	 * @param fpa
	 * @param baseAddr
	 * @param log
	 */
	protected void extractSymbols(ByteProvider provider, FlatProgramAPI fpa, long baseAddr, MessageLog log) {
	
		final int MAX_SYMBOL_LEN = 64;
		
		BinaryReader reader = new BinaryReader(provider, false);
		
		// Scan for symbols
		long len = 0;
		try {
			len = reader.length();
		} catch (IOException e) {
			log.appendException(e);
			return;
		}
		
		while (reader.getPointerIndex() < len) {
			try {
				// Save current address
				long ptr = reader.getPointerIndex();
				
				// Try to read a symbol block
				long symaddr = reader.readNextUnsignedInt();
				long symlen  = reader.readNextUnsignedInt();
				String symname = reader.readNextNullTerminatedAsciiString();

				// Disregard symbols which are blatantly too long
				if (symname.length() > MAX_SYMBOL_LEN) {
					continue;
				}
				
				// See if the symbol name is reasonable
				if ((symname.length() < 2) || !isValidSymbolName(symname)) {
					// Nope. Seek back to the next word boundary and try again.
					reader.setPointerIndex(ptr + 2);
					continue;
				}
				
				// See if the address is reasonable
				if ((symaddr >= baseAddr) && (symaddr <= reader.length()) && (symlen > 0) && (symlen < 0xFFFF)) {
					log.appendMsg(String.format("Symbol found: Addr %08X Sz %4s  -- '%s'", symaddr, symlen, symname));

					try {
						fpa.createLabel(fpa.toAddr(symaddr), symname, true);
					} catch (Exception e) {
						log.appendException(e);
					}
					fpa.createFunction(fpa.toAddr(symaddr), symname);
					fpa.addEntryPoint(fpa.toAddr(symaddr));
				}
				
				// Seek past any padding and onto the next word boundary
				if ((reader.getPointerIndex() % 2) != 0) {
					reader.readNextByte();
				}
			} catch (IOException e) {
				break;
			}
		}
	}
	
}
