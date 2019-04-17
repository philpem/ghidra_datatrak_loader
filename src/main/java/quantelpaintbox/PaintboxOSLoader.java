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
package quantelpaintbox;

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
import ghidra.program.model.data.Undefined1DataType;
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
import jnr.ffi.Struct.Unsigned32;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class PaintboxOSLoader extends AbstractPaintboxLoader {
	
	private static final long OS_LOAD_ADDRESS = 0x400000L;

	@Override
	public String getName() {
		return "Quantel Paintbox VSeries Operating System";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		
		// FIXME Disabled because the ROMs don't have any fixed data we can use to identify them
		
		//BinaryReader reader = new BinaryReader(provider, false);

		//if (reader.readAsciiString(0x100, 4).equals(new String("SEGA"))) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:MC68030", "default"), true));
		//}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		monitor.setMessage(String.format("%s : Start loading", getName()));

		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		// We don't set up vectors because the OS is loaded into RAM and the IVT is in ROM
		
		// RAM-loaded base software
		InputStream romStream = provider.getInputStream(0);
		createSegment(fpa, romStream, "Code (RAM)", OS_LOAD_ADDRESS, romStream.available(),
				true, true, true, false, log);
		
		// Paintbox hardware -- this is common
		createPaintboxHardwareSegments(fpa, provider, program, monitor, log);

		
		// Search for symbols
		monitor.setMessage(String.format("%s : Scanning for symbols", getName()));
			
		// Find the symbol tables -- TODO this only finds one symbol table, we want all of them
		// Another begins at 0x3A6336 with "p_re_parse"
		Address a = fpa.findBytes(null, "FINDMESS");
		if (a != null) {
			log.appendMsg(String.format("Symbol table found at addr: %08X", a.getOffset()));
			log.appendMsg(String.format("Symbol table 2 found at addr: %08X", fpa.findBytes(null, "p_re_parse").getOffset()));
	
			// Symbol table format is <4bytes addr><4bytes length?><ASCIIZ name><optional padding to word boundary>

			// Backtrack to the address field
			reader.setPointerIndex(a.getOffset() - OS_LOAD_ADDRESS - 8);
			
			do {
				long addr = reader.readNextUnsignedInt();
				if (addr == 0) {
					// An address of zero signals the end of the table
					break;
				}
				long len  = reader.readNextUnsignedInt();
				String symbol = reader.readNextAsciiString();
				
				// Skip the padding if we're not lined up on a word boundary
				reader.align(2);
				
				// Create a function at the discovered address and mark its entry point
				try {
					log.appendMsg(String.format("Symbol %s -> 0x%06X len %d (0x%X)", symbol, addr, len, len));
					//fpa.createLabel(fpa.toAddr(addr), symbol, true);
					fpa.createFunction(fpa.toAddr(addr), symbol);
					fpa.addEntryPoint(fpa.toAddr(addr));
				} catch (Exception e) {
					log.appendException(e);
				}
			} while (true);
		} else {
			log.appendMsg("Sorry - couldn't find the symbol table.");
		}
		
		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

}
