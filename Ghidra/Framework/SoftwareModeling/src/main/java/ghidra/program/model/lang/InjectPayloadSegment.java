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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.AddressXML;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

public class InjectPayloadSegment extends InjectPayloadSleigh {

	private AddressSpace space;
	private boolean supportsFarPointer;
	// Back-compat: the first constresolve entry is also stored in these original
	// single fields. Some helper code uses reflection to read these.
	private AddressSpace constResolveSpace;
	private long constResolveOffset;
	private int constResolveSize;

	// New: allow multiple <constresolve> entries (e.g. CS then DS)
	private java.util.ArrayList<AddressSpace> constResolveSpaces;
	private java.util.ArrayList<Long> constResolveOffsets;
	private java.util.ArrayList<Integer> constResolveSizes;

	public InjectPayloadSegment(String source) {
		super(source);
		type = EXECUTABLEPCODE_TYPE;
		space = null;
		supportsFarPointer = false;
		constResolveSpace = null;
		constResolveOffset = 0;
		constResolveSize = 0;
		constResolveSpaces = new java.util.ArrayList<>();
		constResolveOffsets = new java.util.ArrayList<>();
		constResolveSizes = new java.util.ArrayList<>();
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_SEGMENTOP);
		int pos = name.indexOf('_');
		String subName = pos > 0 ? name.substring(0, pos) : name;
		if (!subName.equals("segment")) {
			encoder.writeString(ATTRIB_USEROP, subName);
		}
		encoder.writeSpace(ATTRIB_SPACE, space);
		if (supportsFarPointer) {
			encoder.writeBool(ATTRIB_FARPOINTER, supportsFarPointer);
		}
		super.encode(encoder);
		// Encode constresolve information if present. Prefer the list if it has entries.
		if (!constResolveSpaces.isEmpty()) {
			encoder.openElement(ELEM_CONSTRESOLVE);
			for (int i = 0; i < constResolveSpaces.size(); i++) {
				encoder.openElement(ELEM_VARNODE);
				encoder.writeSpace(ATTRIB_SPACE, constResolveSpaces.get(i));
				encoder.writeUnsignedInteger(ATTRIB_OFFSET, constResolveOffsets.get(i));
				encoder.writeSignedInteger(ATTRIB_SIZE, constResolveSizes.get(i));
				encoder.closeElement(ELEM_VARNODE);
			}
			encoder.closeElement(ELEM_CONSTRESOLVE);
		}
		else if (constResolveSpace != null) {
			// Legacy single-entry encoding
			encoder.openElement(ELEM_CONSTRESOLVE);
			encoder.openElement(ELEM_VARNODE);
			encoder.writeSpace(ATTRIB_SPACE, constResolveSpace);
			encoder.writeUnsignedInteger(ATTRIB_OFFSET, constResolveOffset);
			encoder.writeSignedInteger(ATTRIB_SIZE, constResolveSize);
			encoder.closeElement(ELEM_VARNODE);
			encoder.closeElement(ELEM_CONSTRESOLVE);
		}
		encoder.closeElement(ELEM_SEGMENTOP);
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement el = parser.start();
		name = el.getAttribute("userop");
		if (name == null) {
			name = "segment";
		}
		name = name + "_pcode";
		String spaceString = el.getAttribute("space");
		space = language.getAddressFactory().getAddressSpace(spaceString);
		if (space == null) {
			throw new XmlParseException("Unknown address space: " + spaceString);
		}
		supportsFarPointer = SpecXmlUtils.decodeBoolean(el.getAttribute("farpointer"));
		if (parser.peek().isStart()) {
			if (parser.peek().getName().equals("pcode")) {
				super.restoreXml(parser, language);
			}
			else {
				throw new XmlParseException("Missing <pcode> child for <segmentop> tag");
			}
		}
		if (parser.peek().isStart()) {
			XmlElement subel = parser.start("constresolve");
			// Accept multiple children:
			//   <register name="CS"/>
			//   <register name="DS"/>
			// or legacy:
			//   <varnode space="register" offset="..." size="..."/>
			constResolveSpaces.clear();
			constResolveOffsets.clear();
			constResolveSizes.clear();
			while (parser.peek().isStart()) {
				XmlElement child = parser.start();
				String childName = child.getName();
				if (childName.equals("register")) {
					String regName = child.getAttribute("name");
					if (regName == null) {
						throw new XmlParseException("Missing 'name' attribute for <register> in <constresolve>");
					}
					Register reg = language.getRegister(regName);
					if (reg == null) {
						throw new XmlParseException("Unknown register in <constresolve>: " + regName);
					}
					AddressSpace rspace = reg.getAddress().getAddressSpace();
					long roff = reg.getAddress().getOffset();
					int rsize = reg.getMinimumByteSize();
					constResolveSpaces.add(rspace);
					constResolveOffsets.add(roff);
					constResolveSizes.add(rsize);
					parser.end(child);
				}
				else {
					// Legacy varnode encoding
					AddressXML addrSize = AddressXML.restoreXml(child, language);
					addrSize.getFirstAddress();
					constResolveSpaces.add(addrSize.getAddressSpace());
					constResolveOffsets.add(addrSize.getOffset());
					constResolveSizes.add((int) addrSize.getSize());
					parser.end(child);
				}
			}
			parser.end(subel);

			// Populate the legacy single fields with the first entry (if any)
			if (!constResolveSpaces.isEmpty()) {
				constResolveSpace = constResolveSpaces.get(0);
				constResolveOffset = constResolveOffsets.get(0);
				constResolveSize = constResolveSizes.get(0);
			}
			else {
				constResolveSpace = null;
				constResolveOffset = 0;
				constResolveSize = 0;
			}
		}
		parser.end(el);
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		InjectPayloadSegment op2 = (InjectPayloadSegment) obj;
		// Compare the constresolve lists if present
		if (this.constResolveSpaces.size() != op2.constResolveSpaces.size()) {
			return false;
		}
		for (int i = 0; i < this.constResolveSpaces.size(); i++) {
			if (!SystemUtilities.isEqual(this.constResolveSpaces.get(i), op2.constResolveSpaces.get(i))) {
				return false;
			}
			if (!this.constResolveOffsets.get(i).equals(op2.constResolveOffsets.get(i))) {
				return false;
			}
			if (!this.constResolveSizes.get(i).equals(op2.constResolveSizes.get(i))) {
				return false;
			}
		}
		if (!space.equals(op2.space)) {
			return false;
		}
		if (supportsFarPointer != op2.supportsFarPointer) {
			return false;
		}
		return super.isEquivalent(obj);
	}
}
