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
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
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

		class MemStore {
			final Register baseReg;
			final int disp;
			final String srcRegName;

			MemStore(Register baseReg, int disp, String srcRegName) {
				this.baseReg = baseReg;
				this.disp = disp;
				this.srcRegName = srcRegName;
			}
		}

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		ConstantPropagationContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor,
				trustWriteMemOption) {

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {

				String mnemonic = instr.getMnemonicString();
				if (mnemonic == null) {
					return false;
				}

				// --- restore original LEA anchoring behavior ---
				if ("LEA".equalsIgnoreCase(mnemonic)) {
					Register reg = instr.getRegister(0);
					if (reg != null) {
						BigInteger val = context.getValue(reg, false);
						if (val != null) {
							long lval = val.longValue();
							Address refAddr = instr.getMinAddress().getNewAddress(lval);
							if ((lval > 4096 || lval < 0) && program.getMemory().contains(refAddr)) {
								if (instr.getOperandReferences(1).length == 0) {
									instr.addOperandReference(1, refAddr, RefType.DATA, SourceType.ANALYSIS);
								}
							}
						}
					}
					return false; // match original behavior
				}

				// --- your added MOV-based heuristic(s) ---
				if ("MOV".equalsIgnoreCase(mnemonic)) {
					// run this *only* when it's MOV DX, CS (your helper already gates this)
					detectCsFarPtrReturnAndAnchorBase(program, instr);

					// attempt to detect DS symbols that are indexed like rgplayersdhefs[iPlr]
					anchorIndexedDsTableBase(context, program, instr);
				}

				return false; // match original behavior
			}

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address,
					int size, DataType dataType, RefType refType) {

				// Suppress bogus DS:data refs for "segment literal" patterns like:
				// MOV DX, imm16 (imm16 == current CS)
				// PUSH DX
				//
				// These are commonly used to build far pointers / call frames and should not
				// create a DS:imm16 DATA reference (which spawns DAT_1120_xxxx symbols).
				if (instr != null && "MOV".equalsIgnoreCase(instr.getMnemonicString())) {
					// Must be writing a 16-bit general register (usually DX)
					if (writesRegisterNamed(instr, "DX") || writesRegisterNamed(instr, "AX")
							|| writesRegisterNamed(instr, "CX") || writesRegisterNamed(instr, "BX")
							|| writesRegisterNamed(instr, "SI") || writesRegisterNamed(instr, "DI")) {

						Scalar sc = findFirstImm16Scalar(instr);
						if (sc != null) {
							long imm16 = sc.getUnsignedValue() & 0xffffL;
							long csSeg = getInstructionSegment(instr); // high 16 of address (your model)
							if (csSeg >= 0 && imm16 == (csSeg & 0xffffL)) {

								Instruction next = instr.getNext();
								if (next != null && "PUSH".equalsIgnoreCase(next.getMnemonicString())) {
									// If next reads the same reg we just wrote, treat as "push segment literal"
									// and block reference creation.
									Object[] in = next.getInputObjects();
									if (in != null) {
										for (Object o : in) {
											if (o instanceof Register) {
												Register r = (Register) o;
												// If MOV wrote DX and next PUSH reads DX (common), suppress
												if ((writesRegisterNamed(instr, "DX")
														&& "DX".equalsIgnoreCase(r.getName()))
														|| (writesRegisterNamed(instr, "AX")
																&& "AX".equalsIgnoreCase(r.getName()))
														|| (writesRegisterNamed(instr, "CX")
																&& "CX".equalsIgnoreCase(r.getName()))
														|| (writesRegisterNamed(instr, "BX")
																&& "BX".equalsIgnoreCase(r.getName()))
														|| (writesRegisterNamed(instr, "SI")
																&& "SI".equalsIgnoreCase(r.getName()))
														|| (writesRegisterNamed(instr, "DI")
																&& "DI".equalsIgnoreCase(r.getName()))) {

													log.debug(
															"CP-SUPPRESS: {} suppress DS ref for segment literal imm16=0x{} (CS=0x{})",
															instr.getAddress(), Long.toHexString(imm16),
															Long.toHexString(csSeg));
													return false; // don't create the reference
												}
											}
										}
									}
								}
							}
						}
					}
				}

				// Default behavior
				return super.evaluateReference(context, instr, pcodeop, address, size, dataType, refType);
			}

			private void detectCsFarPtrReturnAndAnchorBase(Program program, Instruction movDxCs) {
				if (program == null || movDxCs == null) {
					return;
				}

				// Trigger: MOV DX, CS
				String mnem0 = movDxCs.getMnemonicString();
				if (!"MOV".equalsIgnoreCase(mnem0)) {
					return;
				}
				if (!writesRegisterNamed(movDxCs, "DX")) {
					return;
				}
				if (!readsRegisterNamed(movDxCs, "CS")) {
					return;
				}

				long seg = getInstructionSegment(movDxCs);
				if (seg < 0) {
					return;
				}

				log.debug("CS-FARPTR: {} confirmed MOV DX,CS (seg={})", movDxCs.getAddress(), Long.toHexString(seg));

				// ---- backward scan: MOV CX, imm16 ----
				Instruction movCxImm = findPrevMovCxImm16(movDxCs, 8);
				if (movCxImm == null) {
					return;
				}

				Scalar sc = findFirstImm16Scalar(movCxImm);
				if (sc == null) {
					return;
				}

				long baseOff = sc.getUnsignedValue() & 0xffffL;
				int movCxImmOpIndex = findOperandIndexContainingImm16ScalarValue(movCxImm, sc.getValue());
				if (movCxImmOpIndex < 0) {
					return;
				}

				log.debug("CS-FARPTR: {} base candidate MOV CX,imm16 at {} imm=0x{}", movDxCs.getAddress(),
						movCxImm.getAddress(), Long.toHexString(baseOff));

				// If baseOff==0, do NOT try to anchor a symbol. This is often "offset-only"
				// farptr build:
				// MOV CX,0; MOV DX,CS; ADD CX,AX; MOV [..],CX; MOV [..+2],DX
				if (baseOff == 0) {
					log.debug("CS-FARPTR: {} baseOff is 0; skipping anchor", movDxCs.getAddress());
					return;
				}

				// ---- forward scan: confirm farptr construction ----
				boolean sawAddCxAx = false;
				boolean sawMovAxCx = false;
				boolean sawStorePair = false;

				Register storeBase = null;
				Integer storeCxDisp = null;
				Integer storeDxDisp = null;

				Instruction cur = movDxCs;
				for (int i = 0; i < 16; i++) { // a little more room; don't rely on linear 8
					cur = cur.getNext();
					if (cur == null) {
						break;
					}

					String mnem = cur.getMnemonicString();
					if (mnem == null) {
						continue;
					}

					// Hard stops only
					if ("CALL".equalsIgnoreCase(mnem) || "RET".equalsIgnoreCase(mnem)
							|| "RETF".equalsIgnoreCase(mnem)) {
						break;
					}

					if ("ADD".equalsIgnoreCase(mnem)) {
						if (writesRegisterNamed(cur, "CX") && readsRegisterNamed(cur, "AX")) {
							sawAddCxAx = true;
							log.debug("CS-FARPTR: {} saw ADD CX,AX at {}", movDxCs.getAddress(), cur.getAddress());
						}
					} else if ("MOV".equalsIgnoreCase(mnem)) {
						// return-style: MOV AX,CX
						if (writesRegisterNamed(cur, "AX") && readsRegisterNamed(cur, "CX")) {
							sawMovAxCx = true;
							log.debug("CS-FARPTR: {} saw MOV AX,CX at {}", movDxCs.getAddress(), cur.getAddress());
						}

						// store-style: MOV word ptr [BASE+disp], CX / DX
						MemStore ms = parseSimpleWordStoreFromReg(cur);
						if (ms != null) {
							if (storeBase == null) {
								storeBase = ms.baseReg;
							}
							// only track one base; if it changes, ignore the store for pairing
							if (storeBase != null && storeBase.equals(ms.baseReg)) {
								if ("CX".equalsIgnoreCase(ms.srcRegName)) {
									storeCxDisp = ms.disp;
								} else if ("DX".equalsIgnoreCase(ms.srcRegName)) {
									storeDxDisp = ms.disp;
								}
								if (storeCxDisp != null && storeDxDisp != null
										&& Math.abs(storeCxDisp - storeDxDisp) == 2) {
									sawStorePair = true;
									log.debug("CS-FARPTR: {} saw store pair base={} cxDisp={} dxDisp={}",
											movDxCs.getAddress(), storeBase.getName(), storeCxDisp, storeDxDisp);
								}
							}
						}
					} else if ("XCHG".equalsIgnoreCase(mnem)) {
						// return-style alternative: XCHG AX,CX
						if ((writesRegisterNamed(cur, "AX") && readsRegisterNamed(cur, "CX"))
								&& (writesRegisterNamed(cur, "CX") && readsRegisterNamed(cur, "AX"))) {
							sawMovAxCx = true;
							log.debug("CS-FARPTR: {} saw XCHG AX,CX at {}", movDxCs.getAddress(), cur.getAddress());
						}
					}

					// Once we know it's a constructed offset and we have either return-style or
					// store-style, stop scanning.
					if (sawAddCxAx && (sawMovAxCx || sawStorePair)) {
						break;
					}
				}

				if (!sawAddCxAx || !(sawMovAxCx || sawStorePair)) {
					return;
				}

				// ---- resolve address ----
				Address target = toSegOff(program, movDxCs.getMinAddress(), seg, baseOff);
				if (target == null) {
					log.debug("CS-FARPTR: {} could not form target CS:{}, seg={}", movDxCs.getAddress(),
							Long.toHexString(baseOff), Long.toHexString(seg));
					return;
				}

				log.debug("CS-FARPTR: {} resolved candidate target {}", movDxCs.getAddress(), target);

				Symbol sym = findDefinedDataSymbol(program, target);
				if (sym == null) {
					log.debug("CS-FARPTR: {} target {} has no defined data symbol", movDxCs.getAddress(), target);
					return;
				}

				log.debug("CS-FARPTR: {} SUCCESS anchor base {} -> {}", movDxCs.getAddress(), movCxImm.getAddress(),
						sym.getAddress());

				addOrPromoteOperandDataRef(program, movCxImm, movCxImmOpIndex, sym.getAddress());
			}

			private void anchorIndexedDsTableBase(VarnodeContext context, Program program, Instruction instr) {
				if (program == null || instr == null || context == null)
					return;
				if (!"MOV".equalsIgnoreCase(instr.getMnemonicString()))
					return;

				if (instr.getNumOperands() < 2)
					return;

				// NEW: if mem operand is ES:/CS:/SS: overridden, don't treat it as DS global
				if (operandHasNonDsSegmentOverride(instr, 1))
					return;

				Object[] res = instr.getResultObjects();
				if (res == null || res.length == 0 || !(res[0] instanceof Register))
					return;

				Object[] srcObjs = instr.getOpObjects(1);
				if (srcObjs == null)
					return;

				Register base = null;
				Scalar dispSc = null;

				for (Object o : srcObjs) {
					if (o instanceof Register) {
						Register r = (Register) o;
						String rn = r.getName();
						if ("BX".equalsIgnoreCase(rn) || "SI".equalsIgnoreCase(rn) || "DI".equalsIgnoreCase(rn)) {
							base = r;
						}
					} else if (o instanceof Scalar) {
						Scalar sc = (Scalar) o;
						if (sc.bitLength() <= 16)
							dispSc = sc;
					}
				}

				if (base == null || dispSc == null)
					return;
				if (instr.getOperandReferences(1).length != 0)
					return;

				Register ds = program.getRegister("DS");
				if (ds == null)
					return;

				BigInteger dsVal = context.getValue(ds, false);
				if (dsVal == null)
					return;

				long seg = dsVal.longValue() & 0xffffL;
				long off1 = dispSc.getUnsignedValue() & 0xffffL;

				Address baseAddr1 = toSegOff(program, instr.getMinAddress(), seg, off1);
				if (baseAddr1 == null)
					return;

				Symbol sym = findDefinedDataSymbol(program, baseAddr1);
				if (sym == null)
					return;

				instr.addOperandReference(1, sym.getAddress(), RefType.DATA, SourceType.ANALYSIS);

				// ---- paired +2 access (segment half of far pointer) ----
				Instruction next = instr.getNext();
				if (next == null)
					return;
				if (!"MOV".equalsIgnoreCase(next.getMnemonicString()))
					return;
				if (next.getNumOperands() < 2)
					return;

				// NEW: also skip if paired access is ES:/CS:/SS: overridden
				if (operandHasNonDsSegmentOverride(next, 1))
					return;

				if (!writesRegisterNamed(next, "DX"))
					return;

				Object[] nextSrcObjs = next.getOpObjects(1);
				if (nextSrcObjs == null)
					return;

				Register base2 = null;
				Scalar dispSc2 = null;

				for (Object o : nextSrcObjs) {
					if (o instanceof Register) {
						Register r = (Register) o;
						if (r.equals(base))
							base2 = r;
					} else if (o instanceof Scalar) {
						Scalar sc = (Scalar) o;
						if (sc.bitLength() <= 16)
							dispSc2 = sc;
					}
				}

				if (base2 == null || dispSc2 == null)
					return;

				long off2 = dispSc2.getUnsignedValue() & 0xffffL;
				if (off2 != ((off1 + 2) & 0xffffL))
					return;

				Address baseAddr2 = toSegOff(program, next.getMinAddress(), seg, off2);
				if (baseAddr2 == null)
					return;

				ReferenceManager rm = program.getReferenceManager();
				for (Reference r : next.getOperandReferences(1)) {
					if (r != null && r.getSource() == SourceType.ANALYSIS)
						rm.delete(r);
				}

				next.addOperandReference(1, sym.getAddress(), RefType.DATA, SourceType.ANALYSIS);
			}

			private boolean operandHasNonDsSegmentOverride(Instruction instr, int opIndex) {
				Object[] objs = instr.getOpObjects(opIndex);
				if (objs == null)
					return false;

				for (Object o : objs) {
					if (o instanceof Register) {
						String rn = ((Register) o).getName();
						if ("ES".equalsIgnoreCase(rn) || "CS".equalsIgnoreCase(rn) || "SS".equalsIgnoreCase(rn)) {
							// Treat any explicit ES/CS/SS as a segment override => not a DS global access
							return true;
						}
						// If DS appears explicitly, that's fine (rare in syntax, but safe)
					}
				}
				return false;
			}

			private MemStore parseSimpleWordStoreFromReg(Instruction instr) {
				if (instr == null) {
					return null;
				}
				if (!"MOV".equalsIgnoreCase(instr.getMnemonicString())) {
					return null;
				}
				if (instr.getNumOperands() < 2) {
					return null;
				}

				// Source must be CX or DX (input objects is the easiest gate)
				boolean srcIsCx = readsRegisterNamed(instr, "CX");
				boolean srcIsDx = readsRegisterNamed(instr, "DX");
				if (!srcIsCx && !srcIsDx) {
					return null;
				}

				// Destination operand (op 0) must look like [REG + disp]
				Object[] dstObjs = instr.getOpObjects(0);
				if (dstObjs == null) {
					return null;
				}

				Register base = null;
				Integer disp = 0;

				for (Object o : dstObjs) {
					if (o instanceof Register) {
						// choose the first register as base (covers [BX+..], [SI+..], etc)
						if (base == null) {
							base = (Register) o;
						}
					} else if (o instanceof Scalar) {
						disp = (int) ((Scalar) o).getSignedValue();
					}
				}

				if (base == null) {
					return null;
				}

				String src = srcIsCx ? "CX" : "DX";
				return new MemStore(base, disp, src);
			}

			private Instruction findPrevMovCxImm16(Instruction start, int maxInstrs) {
				Instruction cur = start;
				for (int i = 0; i < maxInstrs; i++) {
					cur = cur.getPrevious();
					if (cur == null) {
						break;
					}

					String mnem = cur.getMnemonicString();
					if (!"MOV".equalsIgnoreCase(mnem)) {
						continue;
					}

					// MOV CX, imm16
					if (!writesRegisterNamed(cur, "CX")) {
						continue;
					}

					Scalar sc = findFirstImm16Scalar(cur);
					if (sc != null) {
						return cur;
					}
				}
				return null;
			}

			private boolean writesRegisterNamed(Instruction instr, String regName) {
				Object[] res = instr.getResultObjects();
				if (res == null) {
					return false;
				}
				for (Object o : res) {
					if (o instanceof Register && regName.equalsIgnoreCase(((Register) o).getName())) {
						return true;
					}
				}
				return false;
			}

			private boolean readsRegisterNamed(Instruction instr, String regName) {
				Object[] in = instr.getInputObjects();
				if (in == null) {
					return false;
				}
				for (Object o : in) {
					if (o instanceof Register && regName.equalsIgnoreCase(((Register) o).getName())) {
						return true;
					}
				}
				return false;
			}

			private Scalar findFirstImm16Scalar(Instruction instr) {
				for (int op = 0; op < instr.getNumOperands(); op++) {
					Object[] objs = instr.getOpObjects(op);
					if (objs == null) {
						continue;
					}
					for (Object o : objs) {
						if (o instanceof Scalar) {
							Scalar sc = (Scalar) o;
							if (sc.bitLength() <= 16) {
								return sc;
							}
						}
					}
				}
				return null;
			}

			private int findOperandIndexContainingImm16ScalarValue(Instruction instr, long imm16Value) {
				long want = imm16Value & 0xffffL;
				for (int op = 0; op < instr.getNumOperands(); op++) {
					Object[] objs = instr.getOpObjects(op);
					if (objs == null)
						continue;
					for (Object o : objs) {
						if (o instanceof Scalar) {
							Scalar sc = (Scalar) o;
							if (sc.bitLength() <= 16) {
								long got = sc.getUnsignedValue() & 0xffffL;
								if (got == want) {
									return op;
								}
							}
						}
					}
				}
				return -1;
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

				// First: remove competing operand data refs (except user-defined).
				Reference[] refs0 = instr.getOperandReferences(opIndex);
				for (Reference r : refs0) {
					if (r == null) {
						continue;
					}
					if (r.getReferenceType() == null || !r.getReferenceType().isData()) {
						continue;
					}
					if (to.equals(r.getToAddress())) {
						continue;
					}
					// Don't destroy user intent.
					if (r.getSource() == SourceType.USER_DEFINED) {
						continue;
					}
					rm.delete(r);
				}

				// Re-fetch after deletes
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

				// Make this the primary operand ref.
				// Demote any other remaining ANALYSIS data refs (there shouldn't be any now,
				// but keep it sane).
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

}