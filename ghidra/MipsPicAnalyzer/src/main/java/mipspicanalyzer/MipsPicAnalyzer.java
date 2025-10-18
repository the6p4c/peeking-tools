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
package mipspicanalyzer;

import java.math.BigInteger;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MipsPicAnalyzer extends AbstractAnalyzer {
	public MipsPicAnalyzer() {
		super("MIPS PIC Analyzer",
				"Sets the t9 register value in defined functions for position-independent MIPS code.",
				AnalyzerType.FUNCTION_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor() == Processor.toProcessor("MIPS");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();

		Register t9 = program.getRegister("t9");
		Register isaMode = program.getRegister("ISA_MODE");

		// look for defined functions within the address set
		FunctionIterator functions = listing.getFunctions(set, true);
		while (functions.hasNext()) {
			Function function = functions.next();
			Instruction instruction = listing.getInstructionAt(function.getEntryPoint());

			BigInteger t9Value = function.getEntryPoint().getOffsetAsBigInteger();
			boolean isMicroMips = instruction.getValue(isaMode, false).intValue() != 0;
			if (isMicroMips) {
				t9Value = t9Value.add(BigInteger.ONE);
			}

			try {
				instruction.setValue(t9, t9Value);
			} catch (ContextChangeException e) {
				log.appendException(e);
				return false;
			}
		}

		return true;
	}
}
