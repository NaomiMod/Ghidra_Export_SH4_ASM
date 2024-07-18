'''
Ghidra 2 sh4_asm.exe script
By VincentNL 05/06/2024

Based on initial SH4 exporter by Lucas Azevedo (lhsazevedo.dev)
'''

if not currentSelection:
   ghidra.util.Msg.showWarn(None, None, 'Ops', 'Please select some instructions')
   exit()

if currentSelection.getNumAddressRanges() != 1:
   ghidra.util.Msg.showWarn(None, None, 'Ops', 'Only a single selection is supported!')
   exit()

# Get the base address
memory = currentProgram.getMemory()
base_address = memory.getMinAddress()
base_offset = base_address.getOffset()
fullOut = ";base offset:0x{0:x}\n".format(base_offset)

# Get program address
first_address = currentSelection.getFirstRange().getMinAddress()
prog_offset = first_address.getOffset()
fullOut += ";prog offset:0x{0:x}\n".format(prog_offset)

listing = currentProgram.getListing()
codeUnits = listing.getCodeUnits(currentSelection, True)  # true means 'forward'

for cu in codeUnits:
   if issubclass(type(cu), ghidra.program.model.listing.Instruction):
       if cu.getLabel():
           fullOut += '\n' + cu.getLabel() + ":\n"
       out = cu.getMnemonicString().lstrip('_')

       nOp = cu.getNumOperands()
       sep = cu.getSeparator(0)
       if sep != None or nOp != 0:
           out = out.ljust(12)

       if sep != None:
           out += sep

       for i in range(nOp):
           operand_repr = cu.getDefaultOperandRepresentation(i)
           operand = cu.getOpObjects(i)

           # Check if operand is an address and has a label
           if operand:
               for op in operand:
                   if isinstance(op, ghidra.program.model.address.Address):
                       symbol = currentProgram.getSymbolTable().getPrimarySymbol(op)
                       if symbol:
                           operand_repr = operand_repr.replace("0x" + op.toString(), symbol.getName())

           # For consistency reasons it would be ideal to keep # in next sh4_asm.exe updates
           if operand:
               operand_repr = operand_repr.replace("#","")


           out += operand_repr
           sep = cu.getSeparator(i + 1)
           if sep != None:
               out += sep

       if out[0:5].lower() in ['mov.l', 'mov.w', 'mova '] and '@' not in out:
           out = out[:12] + '@' + out[12:]

       fullOut += '          ' + out + '\n'

   elif issubclass(type(cu), ghidra.program.model.listing.Data):

       # Check data type
       data_type = cu.getDataType()

       # Check label
       label = cu.getLabel()

       # Unknown or unassembled address
       if not label:
           label = "unk_{0:#0{1}x}".format(cu.getAddress().getOffset(), 8 + 2)

       # Float stuff
       if isinstance(data_type, ghidra.program.model.data.FloatDataType):
           byte_buffer = java.nio.ByteBuffer.wrap(cu.getBytes())
           byte_buffer.order(java.nio.ByteOrder.LITTLE_ENDIAN)  # Set byte order to little endian
           float_value = byte_buffer.getFloat()
           if label and label.startswith("FLOAT_"):
               fullOut += '\n' + label + ':\n#data ' + str(float_value) + '\n'
           else:
               fullOut += '\n' + "{0:#0{1}x}".format(cu.getAddress().getOffset(), 8 + 2) + ':\n#data ' + str(
                   float_value) + '\n'

       # String stuff
       elif isinstance(data_type, ghidra.program.model.data.StringDataType):

           byte_array = bytearray(cu.getBytes())

           try:
               string_value = byte_array.decode('utf-8')
               fullOut += '\n' + label + ':\n#data "' + string_value[0:-1] + '" 0x00\n' if byte_array[-1] == 0 else '\n' + label + ':\n#data "' + string_value + '"\n'
           except UnicodeDecodeError as e:

               # Handle bytes that cannot be decoded
               decoded_string = byte_array[:e.start].decode('utf-8', errors='ignore')
               fullOut += '\n' + label + ':\n#data "' + decoded_string +'" '
               remaining_bytes = byte_array[e.start:]
               byte_string = ''.join(["{0:#0{1}x} ".format(b, 4) for b in remaining_bytes])
               fullOut += byte_string + '\n'

       # Other data types
       else:

           if len(cu.getBytes()) == 2:
               fullOut += '\n' + label + ':\n#data ' + "{0:#0{1}x}".format(cu.getUnsignedShort(0),
                                                                           4 + 2) + '\n'
           elif len(cu.getBytes()) == 4:
               fullOut += '\n' + label + ':\n#data ' + "{0:#0{1}x}".format(cu.getUnsignedInt(0), 8 + 2) + '\n'
           elif len(cu.getBytes()) == 1:
               fullOut += '\n' + label + ':\n#data ' + "{0:#0{1}x}".format(cu.getUnsignedByte(0), 2 + 2) + '\n'
           else:
               print("Unknown data type... ")
               exit()

# Export file location
out_path = 'c:\mod'

with open(out_path + "\out_0x{0:x}".format(prog_offset) + '.asm', 'w') as f:
   f.write(fullOut.encode('UTF-8'))
