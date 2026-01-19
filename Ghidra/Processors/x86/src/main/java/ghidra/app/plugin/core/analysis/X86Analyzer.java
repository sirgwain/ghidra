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
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class X86Analyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "x86";
	private static final Logger log = LogManager.getLogger(X86Analyzer.class);

	public X86Analyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet,
			final SymbolicPropogator symEval, final TaskMonitor monitor) throws CancelledException {

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		ConstantPropagationContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor,
				trustWriteMemOption) {

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				/*
				 * Win16 segmented-data fix-up: For any operand that contains a 16-bit-ish
				 * scalar constant (e.g. 0x4872), if SEG(instruction):scalar resolves to a
				 * defined DATA symbol (a "variable") in that same segment, make that DATA
				 * symbol the primary operand reference.
				 *
				 * This is intentionally conservative: - does NOT match functions - does NOT
				 * match pure labels without defined data - does NOT use DS/CS heuristics or
				 * nearby idioms
				 */
				anchorImm16OperandsToLocalSegmentVariables(program, instr);
				String mnemonic = instr.getMnemonicString();
				if (mnemonic.equals("LEA")) {
					Register reg = instr.getRegister(0);
					if (reg != null) {
						BigInteger val = context.getValue(reg, false);
						if (val != null) {
							long off = val.longValue() & 0xffffL;

							// IMPORTANT: refuse seg=0 and refuse tiny offsets (keep your noise threshold)
							if (off > 0x100) {
								// If you *really* mean "use the instruction's segment":
								long seg = getInstructionSegment(instr);
								if (seg != 0 && seg > 0) {
									Address target = toSegOff(program, instr.getMinAddress(), seg, off);
									if (target != null) {
										Symbol varSym = findDefinedDataSymbol(program, target);
										if (varSym != null && instr.getOperandReferences(1).length == 0) {
											instr.addOperandReference(1, target, RefType.DATA, SourceType.ANALYSIS);
										}
									}
								}
							}
						}
					}
				}

				return false;
			}

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address,
					int size, DataType dataType, RefType refType) {

				// Keep the default ConstantPropagation behavior; we only add/promote operand
				// refs in evaluateContext().
				return super.evaluateReference(context, instr, pcodeop, address, size, dataType, refType);
			}

			/**
			 * Scan all operands for Scalar constants that look like 16-bit offsets. For
			 * each, attempt to reinterpret it as SEG(instr):off and, if that address
			 * contains a defined-data symbol (variable) in the same segment, add/promote
			 * the operand ref.
			 */
			private void anchorImm16OperandsToLocalSegmentVariables(Program program, Instruction instr) {
				if (program == null || instr == null) {
					return;
				}

				long seg = getInstructionSegment(instr);
				if (seg < 0) {
					return;
				}

				for (int opIndex = 0; opIndex < instr.getNumOperands(); opIndex++) {
					Object[] objs = instr.getOpObjects(opIndex);
					if (objs == null || objs.length == 0) {
						continue;
					}

					for (Object obj : objs) {
						if (!(obj instanceof Scalar)) {
							continue;
						}

						Scalar sc = (Scalar) obj;
						long bitlen = sc.bitLength();
						long off = sc.getUnsignedValue() & 0xffffL;

						// Only imm16-ish scalars; skip larger constants.
						if (bitlen > 16) {
							continue;
						}

						// Skip tiny constants to reduce noise (tweak threshold if you want).
						if (off < 0x0100) {
							continue;
						}

						Address target = toSegOff(program, instr.getMinAddress(), seg, off);
						if (target == null) {
							continue;
						}

						Symbol varSym = findDefinedDataSymbol(program, target);
						if (varSym == null) {
							continue;
						}

						// Must be in the same segment as the instruction (“local code segment” in your
						// wording).
						if (getSegment16(varSym.getAddress()) != seg) {
							continue;
						}

						addOrPromoteOperandDataRef(program, instr, opIndex, varSym.getAddress());
						// One good match per operand is enough.
						break;
					}
				}
			}

			/**
			 * Return the instruction's segment (high 16 bits of the address offset), or -1
			 * if it can't be derived.
			 */
			private long getInstructionSegment(Instruction instr) {
				Address a = instr.getMinAddress();
				if (a == null) {
					return -1;
				}
				return (a.getOffset() >>> 16) & 0xffffL;
			}

			/**
			 * Build a segmented address SEG:OFF in the same address space as 'base'.
			 */
			private Address toSegOff(Program program, Address base, long seg, long off) {
				if (program == null || base == null) {
					return null;
				}
				long flat = ((seg & 0xffffL) << 16) | (off & 0xffffL);
				Address addr = base.getNewAddress(flat);
				if (addr == null || !program.getMemory().contains(addr)) {
					return null;
				}
				return addr;
			}

			/**
			 * Find a "variable" at 'at' by requiring defined data at that address and a
			 * non-default symbol. Rejects: - functions - instruction locations -
			 * default/LAB_ symbols
			 */
			private Symbol findDefinedDataSymbol(Program program, Address at) {
				if (program == null || at == null) {
					return null;
				}

				// Must be defined data (filters pure labels and code).
				Listing listing = program.getListing();
				Data data = listing.getDefinedDataAt(at);
				if (data == null || !data.isDefined()) {
					return null;
				}

				// Must not be code/function.
				if (listing.getInstructionAt(at) != null) {
					return null;
				}
				if (listing.getFunctionAt(at) != null) {
					return null;
				}

				Symbol sym = program.getSymbolTable().getPrimarySymbol(at);
				if (sym == null) {
					return null;
				}

				// Reject auto/default symbols (catches most DAT_/LAB_ noise).
				if (sym.getSource() == SourceType.DEFAULT) {
					return null;
				}

				String name = sym.getName();
				if (name != null && name.startsWith("LAB_")) {
					return null;
				}

				return sym;
			}

			private long getSegment16(Address a) {
				if (a == null) {
					return -1;
				}
				return (a.getOffset() >>> 16) & 0xffffL;
			}

			/**
			 * Ensure there is an operand DATA reference to 'to', and make it the primary
			 * operand reference for that operand index. Demotes other ANALYSIS DATA refs on
			 * that same operand.
			 */
			private void addOrPromoteOperandDataRef(Program program, Instruction instr, int opIndex, Address to) {
				if (program == null || instr == null || to == null) {
					return;
				}

				ReferenceManager rm = program.getReferenceManager();
				Reference[] refs = instr.getOperandReferences(opIndex);

				Reference match = null;
				for (Reference r : refs) {
					if (r != null && to.equals(r.getToAddress()) && r.getReferenceType() != null
							&& r.getReferenceType().isData()) {
						match = r;
						break;
					}
				}

				// Create the reference if it doesn't exist yet.
				if (match == null) {
					instr.addOperandReference(opIndex, to, RefType.DATA, SourceType.ANALYSIS);
					refs = instr.getOperandReferences(opIndex);
					for (Reference r : refs) {
						if (r != null && to.equals(r.getToAddress()) && r.getReferenceType() != null
								&& r.getReferenceType().isData()) {
							match = r;
							break;
						}
					}
				}

				if (match == null) {
					return;
				}

				// Demote other ANALYSIS DATA refs on this operand.
				for (Reference r : refs) {
					if (r == null || r == match) {
						continue;
					}
					if (r.isPrimary() && r.getSource() == SourceType.ANALYSIS && r.getReferenceType() != null
							&& r.getReferenceType().isData()) {
						rm.setPrimary(r, false);
					}
				}

				rm.setPrimary(match, true);
			}
		};

		eval.setTrustWritableMemory(trustWriteMemOption).setMinSpeculativeOffset(minSpeculativeRefAddress)
				.setMaxSpeculativeOffset(maxSpeculativeRefAddress).setMinStoreLoadOffset(minStoreLoadRefAddress)
				.setCreateComplexDataFromPointers(createComplexDataFromPointers);

		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		return resultSet;
	}

	// ---------------------------------------------------------------------------------
	// Win16 segmentation fix-ups
	//
	// In "x86:LE:16:Protected Mode (4.6)" programs used to model Win16 code, the
	// listing's
	// operand navigation depends on analysis-created references. When an
	// instruction uses
	// a CS segment override (e.g., "cs:[bx+0x5b0e]"), we want any concrete
	// reference created
	// by constant propagation to point at the correct segmented address, not the
	// default DS.
	//
	// We currently apply this only for CS overrides and only to non-flow
	// references.
	// ---------------------------------------------------------------------------------
	private enum SegOverride {
		NONE, CS
	}

	private static SegOverride getSegOverrideFromText(Instruction instr) {
		int n = instr.getNumOperands();
		for (int i = 0; i < n; i++) {
			String rep = instr.getDefaultOperandRepresentation(i);
			if (rep == null) {
				continue;
			}
			String r = rep.toLowerCase();
			if (r.contains("cs:")) {
				return SegOverride.CS;
			}
		}
		return SegOverride.NONE;
	}

	private static Address rewriteToSegOff(Address baseForSpace, long seg, Address originalAddr) {
		long off = originalAddr.getOffset() & 0xffffL;
		long flat = ((seg & 0xffffL) << 16) | off;
		return baseForSpace.getNewAddress(flat);
	}

}
