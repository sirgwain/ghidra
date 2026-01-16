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
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		
		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ConstantPropagationContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {
			
			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
			    // --- Win16 CS static table fix-up ---
			    // Always attempt to anchor CS:[...+disp16] to CS:disp16 for listing resolution,
			    // even when constant propagation cannot form a concrete EA.
			    addCsDisp16OperandRefIfPresent(program, instr);
			    addCsLikeImm16OperandRefIfPresent(program, instr);  // NEW: MOV reg, imm16 anchor

				String mnemonic = instr.getMnemonicString();
				if (mnemonic.equals("LEA")) {
					Register reg = instr.getRegister(0);
					if (reg != null) {
						BigInteger val = context.getValue(reg, false);
						if (val != null) {
							long lval = val.longValue();
							Address refAddr = instr.getMinAddress().getNewAddress(lval);
							if ((lval > 4096 || lval < 0) && program.getMemory().contains(refAddr)) {
								if (instr.getOperandReferences(1).length == 0) {
									instr.addOperandReference(1, refAddr, RefType.DATA,
										SourceType.ANALYSIS);
								}
							}
						}
					}
				}
				return false;
			}

			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
					Address address, int size, DataType dataType, RefType refType) {

				// don't allow flow references to locations not in memory if the location is not external.
				if (refType.isFlow() && !instr.getMemory().contains(address) &&
					!address.isExternalAddress()) {
					return false;
				}

//				log.debug("evaluating address" + address.toString());

				// --- Win16 CS segment override fix-up (listing operand refs) ---
				// Only adjust non-flow references, and only when a CS override is present.
				if (!refType.isFlow() && address != null && address.isMemoryAddress()) {
					
					SegOverride ov = getSegOverrideFromText(instr);
					if (ov == SegOverride.CS) {
						log.debug("address: " + address.toString() + ", segOverride: " + ov.toString());
						// Protected-mode hack: derive segment selector from instruction address high 16 bits.
						long seg = (instr.getMinAddress().getOffset() >>> 16) & 0xffffL;
						Address fixed = rewriteToSegOff(instr.getMinAddress(), seg, address);
						if (program.getMemory().contains(fixed) && isKnownCsAddress(program, fixed)) {
						    address = fixed;
						}
					}
				}

				return super.evaluateReference(context, instr, pcodeop, address, size, dataType, refType);
			}

			private Long getSegFromContext(Program program, Address at, String regName) {
				Register reg = program.getRegister(regName);
				if (reg == null) {
					return null;
				}

				RegisterValue rv = program.getProgramContext().getRegisterValue(reg, at);
				if (rv == null) {
					return null;
				}

				BigInteger val = rv.getUnsignedValueIgnoreMask();  // avoids masked/unknown bits
				if (val == null) {
					return null;
				}

				return val.longValue() & 0xffffL;
			}

			private boolean hasNearbyMovRegFromCS(Instruction start, int maxLookahead) {
				Instruction cur = start;
				for (int i = 0; i < maxLookahead; i++) {
					cur = cur.getNext();
					if (cur == null) return false;

					// Stop if control flow breaks (branches/calls/returns)
					FlowType ft = cur.getFlowType();
					if (ft != null && (ft.isJump() || ft.isCall() || ft.isTerminal())) {
						return false;
					}

					if (!"MOV".equalsIgnoreCase(cur.getMnemonicString())) {
						continue;
					}

					// Look for: MOV <reg>, CS
					if (cur.getNumOperands() < 2) continue;

					String srcRep = cur.getDefaultOperandRepresentation(1);
					if (srcRep == null || !srcRep.equalsIgnoreCase("CS")) continue;

					Object[] dstObjs = cur.getOpObjects(0);
					if (dstObjs != null && dstObjs.length == 1 &&
						dstObjs[0] instanceof ghidra.program.model.lang.Register) {
						return true;
					}
				}
				return false;
			}

			
			private void addCsDisp16OperandRefIfPresent(Program program, Instruction instr) {

			    long instrAddr = instr.getMinAddress().getOffset();
			    long seg = (instrAddr >>> 16) & 0xffffL;

			    // High-level entry log (keep INFO for now; you can downgrade to DEBUG later)
//			    log.debug(String.format(
//			        "[CS-TABLE] instr %s  %s",
//			        instr.getMinAddress(),
//			        instr.toString()
//			    ));

			    for (int opIndex = 0; opIndex < instr.getNumOperands(); opIndex++) {

			        String rep = instr.getDefaultOperandRepresentation(opIndex);
			        if (rep == null) {
			            continue;
			        }

			        String r = rep.toLowerCase();
//			        log.debug(String.format(
//			            "[CS-TABLE]   op%d rep='%s'",
//			            opIndex, rep
//			        ));

			        if (!r.contains("cs:")) {
			            continue;
			        }

			        log.debug(String.format(
			            "[CS-TABLE]   >>> CS override detected on op%d",
			            opIndex
			        ));

			        // Look for a 16-bit-ish displacement scalar on this operand
			        for (Object obj : instr.getOpObjects(opIndex)) {

			            if (!(obj instanceof Scalar)) {
			                continue;
			            }

			            Scalar sc = (Scalar) obj;
			            long bitlen = sc.bitLength();
			            long off = sc.getUnsignedValue() & 0xffffL;

			            log.debug(String.format(
			                "[CS-TABLE]     scalar: value=0x%x bitlen=%d",
			                off, bitlen
			            ));

			            // Filter out obvious non-disp scalars
			            if (bitlen > 16) {
			                log.debug("[CS-TABLE]     scalar rejected (bitlen > 16)");
			                continue;
			            }

			            long flat = ((seg & 0xffffL) << 16) | off;
			            Address fixed = instr.getMinAddress().getNewAddress(flat);

			            log.debug(String.format(
			                "[CS-TABLE]     candidate CS:off = %04x:%04x  flat=%s",
			                seg, off, fixed
			            ));

			            if (!program.getMemory().contains(fixed)) {
			                log.debug("[CS-TABLE]     rejected (address not in program memory)");
			                continue;
			            }

			            // Only anchor if the CS target is a known CS symbol (allowing +2 word for 32-bit)
			            if (!isKnownCsAddress(program, fixed)) {
			                log.debug("[CS-TABLE]     rejected (no known CS symbol at target or base-2)");
			                continue;
			            }

			            // SUCCESS: add operand reference
			            instr.addOperandReference(
			                opIndex,
			                fixed,
			                RefType.DATA,
			                SourceType.ANALYSIS
			            );

			            log.debug(String.format(
			                "[CS-TABLE]     *** operand ref ADDED op%d -> %s",
			                opIndex, fixed
			            ));
			            
			            makeOperandRefPrimary(program, instr, opIndex, fixed);


			            return; // one is enough
			        }

			        log.debug(String.format(
			            "[CS-TABLE]   CS override op%d had no usable displacement scalar",
			            opIndex
			        ));
			    }
			}
			
			private void addCsLikeImm16OperandRefIfPresent(Program program, Instruction instr) {

			    // Only MOV
			    String mnem = instr.getMnemonicString();
			    if (mnem == null || !mnem.equalsIgnoreCase("MOV")) {
			        return;
			    }

			    // We only care about MOV reg, imm
			    if (instr.getNumOperands() < 2) {
			        return;
			    }

			    Object[] dstObjs = instr.getOpObjects(0);
			    Object[] srcObjs = instr.getOpObjects(1);

			    if (dstObjs == null || dstObjs.length != 1 ||
			        !(dstObjs[0] instanceof ghidra.program.model.lang.Register)) {
			        return;
			    }
			    if (srcObjs == null || srcObjs.length != 1 || !(srcObjs[0] instanceof Scalar)) {
			        return;
			    }

			    Scalar sc = (Scalar) srcObjs[0];
			    long bitlen = sc.bitLength();
			    long imm = sc.getUnsignedValue() & 0xffffL;

			    // Only imm16-ish
			    if (bitlen > 16) {
			        return;
			    }

			    // Ignore tiny constants
			    if (imm < 0x0100) {
			        return;
			    }

			    Address instrAddr = instr.getMinAddress();
			    long instrOff = instrAddr.getOffset();

			    // --- CS candidate (your protected-mode hack: seg = instruction high16) ---
			    long csSeg = (instrOff >>> 16) & 0xffffL;
			    long csFlat = ((csSeg & 0xffffL) << 16) | imm;
			    Address csAddr = instrAddr.getNewAddress(csFlat);

			    Symbol csSym = null;
			    if (program.getMemory().contains(csAddr)) {
			        csSym = findOwningCsSymbolForWord(program, csAddr); // filters LAB_ and requires defined data
			    }

			    if (csSym != null && !csSym.getAddress().equals(csAddr)) {
			        log.debug(String.format(
			            "[CS-IMM]   note: word %s matched owning 32-bit symbol at %s (%s)",
			            csAddr, csSym.getAddress(), csSym.getName(true)
			        ));
			    }

			    // --- DS candidate (read DS from ProgramContext) ---
			    Symbol dsSym = null;
			    Address dsAddr = null;

			    Long dsSegObj = getSegFromContext(program, instrAddr, "DS");
			    if (dsSegObj != null) {
			        long dsSeg = dsSegObj.longValue() & 0xffffL;
			        long dsFlat = ((dsSeg & 0xffffL) << 16) | imm;
			        dsAddr = instrAddr.getNewAddress(dsFlat);
			        if (program.getMemory().contains(dsAddr)) {
			            dsSym = program.getSymbolTable().getPrimarySymbol(dsAddr);
			            if (!isUsableDataSymbol(program, dsSym, dsAddr, 2)) {
			                dsSym = null;
			                dsAddr = null;
			            }
			        }
			    }

			    // If we have a DS symbol match and no CS symbol match, explicitly create DS ref (restore old behavior).
			    if (dsSym != null && csSym == null) {
			        instr.addOperandReference(1, dsAddr, RefType.DATA, SourceType.ANALYSIS);
			        makeOperandRefPrimary(program, instr, 1, dsAddr);

			        log.debug(String.format(
			            "[CS-IMM] %s %s imm=0x%04x -> prefer DS sym=%s (csSym=null) (DS ref added)",
			            instr.getMinAddress(), instr.toString(), imm, dsSym.getName(true)
			        ));
			        return;
			    }

			    // If CS has no symbol, we have nothing to do
			    if (csSym == null) {
			        return;
			    }

			    // If both DS and CS have symbols, default to DS unless we see the far-pointer idiom.
			    if (dsSym != null) {
			        if (!hasNearbyMovRegFromCS(instr, 6)) {

			            // We decided to keep DS: explicitly create the DS ref as well.
			            instr.addOperandReference(1, dsAddr, RefType.DATA, SourceType.ANALYSIS);
			            makeOperandRefPrimary(program, instr, 1, dsAddr);

			            log.debug(String.format(
			                "[CS-IMM] %s %s imm=0x%04x -> both DS(%s) and CS(%s) have symbols; keeping DS (no MOV reg,CS nearby) (DS ref added)",
			                instr.getMinAddress(), instr.toString(), imm,
			                dsSym.getName(true), csSym.getName(true)
			            ));
			            return;
			        }
			        // else: allow CS override below
			    } else {
			        // If DS has no symbol, still require the idiom gate (keeps false positives low)
			        if (!hasNearbyMovRegFromCS(instr, 6)) {
			            return;
			        }
			    }

			    // Add CS operand reference and make primary
			    log.debug(String.format(
			        "[CS-IMM] %s  %s  => CS %04x:%04x (%s) sym=%s",
			        instr.getMinAddress(),
			        instr.toString(),
			        csSeg, imm,
			        csAddr,
			        csSym.getName(true)
			    ));

			    instr.addOperandReference(1, csAddr, RefType.DATA, SourceType.ANALYSIS);
			    makeOperandRefPrimary(program, instr, 1, csAddr);

			    log.debug(String.format(
			        "[CS-IMM]   *** operand ref ADDED/PRIMARY op1 -> %s",
			        csAddr
			    ));
			}


			
			private void makeOperandRefPrimary(Program program, Instruction instr, int opIndex, Address wantPrimary) {

			    ReferenceManager rm = program.getReferenceManager();
			    Reference[] refs = instr.getOperandReferences(opIndex);

			    Reference primaryRef = null;

			    // Find the ref we just added (or an existing matching one)
			    for (Reference ref : refs) {
			        if (ref == null) continue;
			        if (wantPrimary.equals(ref.getToAddress())) {
			            primaryRef = ref;
			            break;
			        }
			    }

			    if (primaryRef == null) {
			        log.debug(String.format(
			            "[CS-TABLE]     could not find newly-added operand ref for op%d -> %s",
			            opIndex, wantPrimary
			        ));
			        return;
			    }

			    // Demote other ANALYSIS DATA refs on the same operand
			    for (Reference ref : refs) {
			        if (ref == null) continue;
			        if (ref == primaryRef) continue;

			        if (ref.getSource() == SourceType.ANALYSIS && ref.getReferenceType() != null && ref.getReferenceType().isData()) {
			            if (ref.isPrimary()) {
			                rm.setPrimary(ref, false);
			                log.debug(String.format(
			                    "[CS-TABLE]     demoted primary op%d ref %s -> %s",
			                    opIndex, ref.getFromAddress(), ref.getToAddress()
			                ));
			            }
			        }
			    }

			    // Promote our CS one
			    rm.setPrimary(primaryRef, true);
			    log.debug(String.format(
			        "[CS-TABLE]     promoted CS ref to PRIMARY op%d -> %s",
			        opIndex, wantPrimary
			    ));
			}

			private void deleteCompetingOperandRefs(
			        Program program,
			        Instruction instr,
			        int opIndex,
			        Address keepAddress) {

			    ReferenceManager rm = program.getReferenceManager();

			    for (Reference ref : instr.getOperandReferences(opIndex)) {

			        if (ref == null) continue;

			        // Keep the one we just added
			        if (keepAddress.equals(ref.getToAddress())) {
			            continue;
			        }

			        // Only delete ANALYSIS-generated DATA refs
			        if (ref.getSource() == SourceType.ANALYSIS &&
			            ref.getReferenceType() != null &&
			            ref.getReferenceType().isData()) {

			            log.debug(String.format(
			                "[CS-IMM]   deleting competing op%d ref -> %s (primary=%s)",
			                opIndex,
			                ref.getToAddress(),
			                ref.isPrimary()
			            ));

			            rm.delete(ref);
			        }
			    }
			}

			private Symbol findOwningCsSymbolForWord(Program program, Address csAddr) {

			    // Exact symbol at this word
			    Symbol sym = program.getSymbolTable().getPrimarySymbol(csAddr);
			    if (isUsableDataSymbol(program, sym, csAddr, 2)) {
			        return sym;
			    }

			    // If this word is the high word of a 32-bit CS symbol, it will be at base+2.
			    Address base = csAddr.subtract(2);
			    Symbol baseSym = program.getSymbolTable().getPrimarySymbol(base);
			    if (!isUsableDataSymbol(program, baseSym, base, 4)) {
			        return null;
			    }

			    return baseSym;
			}


			private boolean isKnownCsAddress(Program program, Address csAddr) {
			    return findOwningCsSymbolForWord(program, csAddr) != null;
			}

			private boolean isUsableDataSymbol(Program program, Symbol sym, Address at, int minLen) {
			    if (program == null || sym == null || at == null) {
			        return false;
			    }

			    // Reject auto/default symbols (this catches most LAB_*)
			    if (sym.getSource() == SourceType.DEFAULT) {
			        return false;
			    }

			    // Explicitly reject "LAB_*" even if they came from some analysis/import edge case
			    String name = sym.getName();
			    if (name != null && name.startsWith("LAB_")) {
			        return false;
			    }

			    // Require defined data at the address (prevents matching code labels)
			    Listing listing = program.getListing();
			    Data data = listing.getDefinedDataAt(at);
			    if (data == null || !data.isDefined()) {
			        return false;
			    }

			    return data.getLength() >= minLen;
			}

			
		};
	
		eval.setTrustWritableMemory(trustWriteMemOption)
		    .setMinSpeculativeOffset(minSpeculativeRefAddress)
		    .setMaxSpeculativeOffset(maxSpeculativeRefAddress)
		    .setMinStoreLoadOffset(minStoreLoadRefAddress)
		    .setCreateComplexDataFromPointers(createComplexDataFromPointers);
		
		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		return resultSet;
	}

	// ---------------------------------------------------------------------------------
	// Win16 segmentation fix-ups
	//
	// In "x86:LE:16:Protected Mode (4.6)" programs used to model Win16 code, the listing's
	// operand navigation depends on analysis-created references. When an instruction uses
	// a CS segment override (e.g., "cs:[bx+0x5b0e]"), we want any concrete reference created
	// by constant propagation to point at the correct segmented address, not the default DS.
	//
	// We currently apply this only for CS overrides and only to non-flow references.
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
