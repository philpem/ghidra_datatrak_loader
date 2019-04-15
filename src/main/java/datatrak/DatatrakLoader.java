/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package datatrak;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import docking.widgets.OptionDialog;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class DatatrakLoader extends AbstractLibrarySupportLoader {

	private VectorTable vectors;

	@Override
	public String getName() {
		return "Datatrak M68000 firmware";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		
		// FIXME Disabled because the Datatrak ROMs don't have any fixed data we can use to identify them
		
		//BinaryReader reader = new BinaryReader(provider, false);

		//if (reader.readAsciiString(0x100, 4).equals(new String("SEGA"))) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:MC68020", "default"), true));
		//}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		monitor.setMessage(String.format("%s : Start loading", getName()));

		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		vectors = new VectorTable(fpa, reader);
		//header = new GameHeader(reader);

		createSegments(fpa, provider, program, monitor, log);
		markVectorTable(program, fpa, log);
		//markHeader(program, fpa, log);

		
		// TODO: Find the Initialized Data block and set it up as a mirror segment
		// TODO Scan from the RESET entry point to find the CRT0 (initialisation) code 

		long initPC = vectors.getReset().getAddress().getOffset();
		
		// Pattern to match; -1 means the byte is not requ
		int[] pattern = {
				0x41, 0xF9, 0x00, 0x20, 0x00, 0x00,		// LEA    (0x200000).L, A0     ; start of dseg in RAM
				0x20, 0x3C, 0x00, -1, -1, -1,			// MOVE.L #EndOfDataSeg, D0    ; end of dseg in RAM
				0x90, 0x88,								// SUB.L  A0, D0               ; D0 = D0 - A0
				0x43, 0xF9, 0x00, -1, -1, -1,			// LEA    (StartOfData), A1    ; start of dseg initialisation data
				0x53, 0x80,								// SUBQ.L #1, D0               ; D0 --
				0x10, 0xD9,								// MOVE.B (A1)+, (A0)+         ; *a0++ = *a1++
				0x51, 0xC8, 0xFF, 0xFC					// DBF    D0, $-2              ; decrement d0, branch if >= 0
		};
		
		// Sliding window buffer -- TODO prefill with data from initPC
		ArrayList<Integer> window = new ArrayList<>();
		for (int i=0; i<pattern.length; i++) {		// FIXME prefills with zeroes
			window.add(0);
		}
		//reader.readByteArray(initPC, pattern.length);

		Boolean match = true;
		long matchAddress = 0;

		log.appendMsg(String.format("SLIDE: Initial PC = %08X",  initPC));
		
		// Scan from the initial PC to a reasonable spot past it 
		for (long addr=initPC; addr < initPC + 0x100; addr++) {
			// Remove first byte (this is a sliding-window FIFO)
			window.remove(0);
			window.add((reader.readByte(addr)) & 0xFF);

			// Check for a window match
			match = true;
			for (int i=0; i<pattern.length; i++) {
				if ((pattern[i] != -1) && (pattern[i] != window.get(i))) {
					match = false;
					break;
				}
			}
			
			// Exit the loop if we found a match
			if (match) {
				matchAddress = addr - pattern.length + 1;
				break;
			}
		}
		
		if (match) {
			// Extract useful pointers from the IDATA copy code
			long dsegRamStart = reader.readUnsignedInt(matchAddress+2);
			long dsegRamEnd   = reader.readUnsignedInt(matchAddress+8);
			long dsegRomStart = reader.readUnsignedInt(matchAddress+16);
			
			log.appendMsg(String.format("%s: Creating IDATA segment -- RAM 0x%06X to 0x%06X, copied from 0x%06X", getName(), dsegRamStart, dsegRamEnd, dsegRomStart));
			
			// Calculate IDATA segment length and ROM end address
			long dsegLen = dsegRamEnd - dsegRamStart;
			//long dsegRomEnd = dsegRomStart + dsegLen;
			
			createMirrorSegment(program.getMemory(), fpa, "IDATA", dsegRomStart, dsegRamStart, dsegLen, log);
			createSegment(fpa, null, "RAM1", dsegRamEnd, 0x20000-dsegLen, true, true, true, false, log);		// TODO Validate RAM area addresses
			createSegment(fpa, null, "RAM2", 0x220000, 0x20000, true, true, true, false, log);		// TODO Validate RAM area addresses
		} else {
			log.appendMsg("Caution: IDATA segment initialiser not found -- IDATA segment data not copied!");
			createSegment(fpa, null, "RAM1", 0x200000, 0x20000, true, true, true, false, log);		// TODO Validate RAM area addresses
			createSegment(fpa, null, "RAM2", 0x220000, 0x20000, true, true, true, false, log);		// TODO Validate RAM area addresses
		}
		
		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	private void createSegments(FlatProgramAPI fpa, ByteProvider provider, Program program, TaskMonitor monitor,
			MessageLog log) throws IOException {
		InputStream romStream = provider.getInputStream(0);

		// ROM
		createSegment(fpa, romStream, "ROM", 0x000000L, Math.min(romStream.available(), 0x1FFFFFL),
				true, false, true, false, log);
				
		
		// RAM segments are created once IDATA is known
		
		
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
		
		createSegment(fpa, null, "IO_DUART",	0x240300, 256, true, true, false, true, log);	// SCC68692 Dual UART
		Structure duart = new StructureDataType("DUART", 0);
		duart.add(WordDataType.dataType, 2, "MR1A_MR2A",	"R/W: Mode register A (MR1A, MR2A)");
		duart.add(WordDataType.dataType, 2, "SRA_CSRA",		"R: Status Reg A\nW:Clk Sel Reg A");
		duart.add(WordDataType.dataType, 2, "BRGT_CRA",		"R: BRG test\nW:Cmd Reg A");
		duart.add(WordDataType.dataType, 2, "RHRA_THRA",	"R: Rx Buf A\nW:Tx Buf A");
		duart.add(WordDataType.dataType, 2, "IPCR_ACR",		"R: Input port change reg\nW: Aux control reg");
		duart.add(WordDataType.dataType, 2, "ISR_IMR",		"R: Interrupt status reg\nW: Interrupt mask reg");
		duart.add(WordDataType.dataType, 2, "CTU_CTUR",		"R: MSB of counter in counter mode\nW:C/T upper preset value");
		duart.add(WordDataType.dataType, 2, "CTL_CTLR",		"R: MSB of counter in counter mode\nW:C/T upper preset value");
		duart.add(WordDataType.dataType, 2, "MR1B_MR2B",	"R/W: Mode Register B (MR1B, MR2B)");
		duart.add(WordDataType.dataType, 2, "SRB_CSRB",		"R: Status Reg B\nW:Clk Sel Reg B");
		duart.add(WordDataType.dataType, 2, "1XTEST_CRB",	"R: 1x/16x Test\nW: Cmd Reg B");
		duart.add(WordDataType.dataType, 2, "RHRB_THRB",	"R: Rx Buf B\nW:Tx Buf B");
		duart.add(WordDataType.dataType, 2, "IVR",			"R/W: Interrupt vector register");
		duart.add(WordDataType.dataType, 2, "INP_OPCR",		"R: Input ports IP0-IP6\nW: Output Port Config Register");
		duart.add(WordDataType.dataType, 2, "START_OBS",	"R: Start Counter command\nW: Set Output Port Bits Command");
		duart.add(WordDataType.dataType, 2, "STOP_OBR",		"R: Stop Counter command\nW: Reset Output Port Bits Command");
		try {
			DataUtilities.createData(program, fpa.toAddr(0x240300), duart, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			program.getSymbolTable().createLabel(fpa.toAddr(0x240300), "IO_DUART", SourceType.IMPORTED);
		} catch (CodeUnitInsertionException | InvalidInputException e) {
			log.appendException(e);
		}


		createSegment(fpa, null, "IO_UNK_04",	0x240400, 256, true, true, false, true, log);

		createSegment(fpa, null, "IO_UNK_05",	0x240500, 256, true, true, false, true, log);

		createSegment(fpa, null, "IO_UNK_06",	0x240600, 256, true, true, false, true, log);

		createSegment(fpa, null, "IO_UNK_07",	0x240700, 256, true, true, false, true, log);

		createSegment(fpa, null, "IO_UNK_08",	0x240800, 256, true, true, false, true, log);

		//createSegment(fpa, null, "IO_UNDEFINED",0x240900, 0x250000-0x240900, true, true, false, true, log);		// Undefined, no peripherals assigned

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
	private void markVectorTable(Program program, FlatProgramAPI fpa, MessageLog log) {
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
	private void createNamedArray(FlatProgramAPI fpa, Program program, long address, String name, int numElements, DataType type, MessageLog log) {
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
	private void createNamedData(FlatProgramAPI fpa, Program program, long address, String name, DataType type, MessageLog log) {
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

	private void createNamedData(FlatProgramAPI fpa, Program program, long address, String name, String comment, DataType type, MessageLog log) {
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
	private void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size,
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
	private void createMirrorSegment(Memory memory, FlatProgramAPI fpa, String name, long base, long new_addr,
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
}
