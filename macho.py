#!/usr/bin/python
'''
mach-o binary dump/undump utility
'''
import sys, os, struct, ast, logging, re
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)
HEADER = {}
SEGMENTS = []
ADDRESSES = {}
HEADER_SIZE = 4 * 7
PREFETCH = 8  # 2 words or 8 bytes
SHIFT_TYPE = {
    0: 'LSL',
    'LSL': 0,
    1: 'LSR',
    'LSR': 1,
    2: 'ASR',
    'ASR': 2,
    3: 'ROR',
    'ROR': 3,
}
CONDITION_CODES = [
    'EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC',
    'HI', 'LS', 'GE', 'LT', 'GT', 'LE', '', 'undefined'
]
TEST_CODES = ['TST', 'TEQ', 'CMP', 'CMN']
DATA_PROCESSING_CODES = ['AND', 'EOR', 'SUB', 'RSB', 'ADD', 'ADC',
    'SBC', 'RSC'] + TEST_CODES + ['ORR', 'MOV', 'BIC', 'MVN']
BRANCH_CODES = ['BL', 'B']
SINGLE_DATA_TRANSFER_CODES = ['LDR', 'STR']
REGISTER_NAMES = {
    'R13': 'SP',
    'SP': 'R13',
    'R14': 'LR',
    'LR': 'R14',
    'R15': 'PC',
    'PC': 'R15',
}
MNEMONICS = (  # longest to shortest
    DATA_PROCESSING_CODES +
    BRANCH_CODES +
    SINGLE_DATA_TRANSFER_CODES
)
ASSEMBLED_PATTERN = re.compile(r'#\s+(0x[0-9a-f]+):\s+(0x[0-9a-f]+)\s')
MASK32 = (1 << 32) - 1
MASK12 = (1 << 12) - 1
MASK4 = 0xf
MASK8 = 0xff

def dump(binary):
    offset = dumpheader(binary)
    offset = dumpsegments(binary, offset)
    while offset < len(binary):
        try:
            dump_instruction(binary[offset:offset + 4],
                             comment=buildcomment(binary, offset))
        except ValueError:
            dumplong(binary[offset:offset + 4],
                     buildcomment(binary, offset))
        offset += 4

def extract_comment(comment=''):
    try:
        offset, assembled = ASSEMBLED_PATTERN.match(comment).groups()
    except AttributeError:
        logging.debug('No match of %s with %s' % (
            ASSEMBLED_PATTERN.pattern, comment))
        offset, assembled = None, None
    return offset, assembled

def undump(lines):
    for line in lines:
        #logging.debug('undumping line %s' % line)
        line, tokens, comment = tokenize(line)
        try:
            offset, assembled = ASSEMBLED_PATTERN.match(comment).groups()
            #logging.debug('found assembled: %s' % assembled)
        except:
            offset, assembled = None, None
        if not tokens or tokens[0].endswith(':'):
            continue
        elif tokens[0] == '.long':
            for word in tokens[1:]:
                if word.startswith(';'):
                    break
                sys.stdout.write(struct.pack('<I', safeint(word)))
        elif tokens[0] == '.byte':
            for word in tokens[1:]:
                if word.startswith(';'):
                    break
                sys.stdout.write(chr(safeint(word)))
        elif tokens[0] == '.ascii':
            sys.stdout.write(get_quoted(line))
        elif tokens[0] == '.asciz':
            sys.stdout.write(get_quoted(line) + '\0')
        else:
            sys.stdout.write(undump_instruction(
                tokens, safeint(offset), safeint(assembled)))

def get_quoted(string):
    '''
    return that part of the string between "double quotes"
    '''
    start = string.index('"') + 1
    end = string.rindex('"')
    return string[start:end]

def undump_instruction(tokens, offset=None, last_assembled=None):
    '''
    convert ARM instruction back into bytes

    >>> undump_instruction(['bic', 'sp,', 'sp,', '#7'], 0x4d5c, 0xe3cdd007)
    '\\x07\\xd0\\xcd\\xe3'

    >>> undump_instruction(['bl', '0x4eb8'], 0x4dc4, 0xeb00003b)
    ';\\x00\\x00\\xeb'
    '''
    encoded = None
    'order undumper routines so that shortest instructions are last'
    for undumper in [undump_dp_instruction, undump_ldr_str_instruction,
                     undump_branch_instruction]:
        try:
            encoded = undumper(tokens, offset, last_assembled)
            break
        except:
            continue
    if encoded is None:
        raise(ValueError('No way found to undump %r' % tokens))
    '''
    in case of, say, a string being interpreted as an instruction, it could
    be a non-optimally assembled instruction, and thus won't have reassembled
    into the same string. we correct that here, e.g.:

    74051c74051
    <     subvs r6, pc, #7602176  ;# 0x48584: 0x624f6874 'thob' 
    ---
    >     subvs r6, pc, #7602176  ;# 0x48584: 0x624f671d '\x1dgob'
    '''
    test_comment = '0x%x: 0x0' % offset
    if (last_assembled is not None and encoded != last_assembled and
        dump_instruction(struct.pack('<I', last_assembled),
            comment=test_comment, output=False) == tokens):
        logging.info('using suboptimal encoding as found in previous binary')
        encoded = last_assembled
    return struct.pack('<I', encoded)

def get_condition_code_value(string):
    '''
    find 2-character condition code at beginning of string or assume ''
    
    return number representing the code
    '''
    code = string[:2] if string[:2] in CONDITION_CODES else ''
    condition_code = CONDITION_CODES.index(code)
    return condition_code, string[len(code):]

def undump_dp_instruction(tokens, offset=None, last_assembled=None):
    '''
    undump (assemble) data processing instruction
    '''
    mnemonic = tokens[0].upper()
    if mnemonic[:3] in DATA_PROCESSING_CODES:
        instruction, remainder = mnemonic[:3], mnemonic[3:]
        condition_code, remainder = get_condition_code_value(remainder)
        set_condition_codes = remainder == 'S' or instruction in TEST_CODES
        if remainder not in ['S', '']:
            raise(ValueError('No such instruction "%s"' % instruction))
        encoded = DATA_PROCESSING_CODES.index(instruction) << 21
        encoded |= condition_code << 28
        encoded |= set_condition_codes << 20
        encoded |= destination_register(tokens[1].upper())
        encoded |= first_operand(tokens[2].upper())
        encoded |= second_operand(tokens[3:])
        return encoded
    raise(ValueError('No DP instruction found in %s' % tokens))

def undump_ldr_str_instruction(tokens, offset=None, last_assembled=None):
    '''
    undump (assemble) a LDR or STR instruction

    >>> '0x%x' % undump_ldr_str_instruction(
    ...  ['ldr', 'r0,', '[sp,', '#0x0]'], 0x4d4c, 0x0)
    '0xe59d0000'
    '''
    mnemonic = tokens[0].upper()
    if mnemonic.startswith(('LDR', 'STR')):
        instruction, remainder = mnemonic[:3], mnemonic[3:]
        condition_code, remainder = get_condition_code_value(remainder)
        encoded = 0b01 << 26  # common to LDR and STR, 0x04000000
        encoded |= condition_code << 28  # 0xN0000000
        immediate = (not tokens[-1].startswith('#')) << 25  # 0x02000000
        preindex = (not (tokens[2].startswith('[') and
                         tokens[2].endswith('],'))) << 24
        direction = (not tokens[-1].startswith(('-', '#-'))) << 23
        encoded |= immediate | preindex | direction
        encoded |= bool('B' in remainder) << 22
        encoded |= (bool('T' in remainder) or tokens[-1].endswith('!')) << 21
        encoded |= mnemonic.startswith('L') << 20
        if remainder.replace('B', '', 1).replace('T', '', 1):
            raise(ValueError('Invalid LDR/STR instruction %s' % mnemonic))
        encoded |= destination_register(tokens[1].upper()) << 12
        encoded |= first_operand(tokens[2].upper())  # base register
        return encoded
    raise(ValueError('Not a valid LDR or STR instruction: %s' % tokens))

def undump_branch_instruction(tokens, offset=None, last_assembled=None):
    '''
    undump (assemble) a branch instruction

    >>> '0x%x' % undump_branch_instruction(['bls', '0x66d8'], 0x66b0, 0x0)
    '0x9a000008'
    '''
    #logging.debug('undumping %s' % tokens)
    mnemonic = tokens[0].upper()
    if mnemonic.startswith('B'):
        for instruction in ['BL', 'B']:
            remainder = mnemonic[len(instruction):]
            encoded = (0b101 << 25) | ((instruction == 'BL') << 24)
            condition_code, remainder = get_condition_code_value(remainder)
            encoded |= condition_code << 28
            branch_offset = (safeint(tokens[1]) - offset - PREFETCH) >> 2
            encoded |= branch_offset
            if not remainder:
                return encoded
    raise(ValueError('No valid branch instruction found in %s' % tokens))

def tokenize(line):
    '''
    split assembly source into tokens, returning comment separately as string
    '''
    try:
        line, comment = line.split(';', 1)
    except ValueError:
        line, comment = line, ''
    return line, line.split(), comment
def destination_register(token, shifted = 12):
    '''
    return encoded destination register

    >>> destination_register('R12,')
    49152
    '''
    register_name = named_register(token.rstrip(','))
    register_number = int(register_name[1:])
    if not register_name.startswith('R') or not (0 <= register_number <= 15):
        raise(ValueError('Bad register %s' % token))
    return register_number << shifted

def second_operand(tokens):
    '''
    register with shift count, or immediate
    '''
    if len(tokens) == 1:
        if tokens[0].startswith('#'):
            number = safeint(tokens[0][1:])
            packed_number = packnumber(number)
            immediate = 1 << 25  # set bit to indicate immediate argument
            return packed_number | immediate
        else:
            return first_operand(tokens[0].upper(), shifted = 0)
    else:
        register = first_operand(tokens[0].upper(), shifted = 0)
        shift_type = SHIFT_TYPE[tokens[1].upper()] << 1
        if tokens[2].startswith('#'):
            shift = ((safeint(tokens[2][1:]) % 32) << 3) | shift_type
        else:
            shift = first_operand(tokens[2].upper(), shifted = 4)
            shift = shift | shift_type | 1
        return register | (shift << 4)


def first_operand(token, shifted = 16):
    '''
    return encoded first operand

    >>> first_operand('R1,')
    65536
    '''
    register_name = named_register(token.rstrip(',').rstrip(']').lstrip('['))
    register_number = int(register_name[1:])
    if not register_name.startswith('R') or not (0 <= register_number <= 15):
        raise(ValueError('Bad register %s' % token))
    return register_number << shifted

def named_register(register_name):
    '''
    return special name for register if one exists, otherwise its Rn name
    '''
    return REGISTER_NAMES.get(register_name, register_name)

def dump_instruction(binary, comment='', output=True):
    '''
    disassemble an instruction

    comment will be shown following ';#' in the dumped source.
    if output=None, disables printing, for use with check code in undump
    '''
    for dumper in [dump_dp_instruction, dump_branch_instruction,
                   dump_ldr_str_instruction]:
        try:
            return dumper(binary, comment, output)
        except:
            continue
    raise(ValueError('No way found to dump %r' % binary))

def unpack_word(binary):
    '''
    unpack 32-bit word from 4-byte string
    '''
    try:
        word = struct.unpack('<I', binary)[0]
    except:
        raise(ValueError('Cannot unpack %r into word' % binary))
    return word

def get_condition_code(opcode, shift=28):
    condition_code = CONDITION_CODES[(opcode >> shift) & MASK4]
    if condition_code == 'undefined':
        raise(ValueError('Invalid branch instruction 0x%x' % opcode))
    return condition_code

def dump_ldr_str_instruction(binary, comment='', output=True):
    '''
    disassemble a single data transfer instruction

    >>> dump_ldr_str_instruction(struct.pack('<I', 0xe59f3030), '0x49470: 0x0')
        ldr r3, [pc, #0x30]  ;# 0x49470: 0x0
    ['ldr', 'r3,', '[pc,', '#0x30]']
    '''
    #logging.debug('dumping instruction %r, comment=%s' % (binary, comment))
    opcode = unpack_word(binary)
    condition_code = get_condition_code(opcode)
    mnemonic = ['STR', 'LDR'][(opcode >> 20) & 1]
    if (opcode >> 26) & 0b11 != 0b01:
        raise(ValueError('Not LDR not STR'))
    write_back = ['', '!'][bit(21, opcode)]
    byte_transfer = ['', 'B'][bit(22, opcode)]
    direction = ['', '-'][not bit(23, opcode)]
    preindex = bit(24, opcode)  # add offset 1=pre, 0=post load or store
    set_t = ['', 'T'][bool(write_back and not preindex)]
    immediate = not bit(25, opcode)
    target_register = named_register('R%d' % ((opcode >> 12) & MASK4))
    base_register = named_register('R%d' % ((opcode >> 16) & MASK4))
    if immediate:
        offset = '#%s0x%x' % (direction, opcode & MASK12)
    else:
        offset = register_shift((opcode >> 4) & MASK8, base_register, direction)
    if preindex:
        expanded = '    %s%s%s%s %s, [%s, %s]%s  ;# %s' % (
            mnemonic, condition_code, byte_transfer, set_t,
            target_register, base_register, offset, write_back, comment or '')
    else:
        expanded = '    %s%s%s%s %s, [%s], %s  ;# %s' % (
            mnemonic, condition_code, byte_transfer, set_t,
            target_register, base_register, offset, comment or '')
    return process_output(expanded, output)

def bit(index, value):
    '''
    return the value of bit at value[index]
    
    >>> bit(2, 0b100)
    1

    >>> bit(1, 0b100)
    0
    '''
    return (value >> index) & 1

def process_output(sourceline, output=True):
    output_ready = sourceline.lower()
    if output:
        print output_ready
    return tokenize(output_ready)[1]

def dump_branch_instruction(binary, comment='', output=True):
    '''
    disassemble a branch instruction

    >>> dump_branch_instruction(struct.pack('<I', 0xeb000000), '0x4d60: 0x0')
        bl 0x4d68  ;# 0x4d60: 0x0
    ['bl', '0x4d68']
    '''
    #logging.debug('dumping instruction %r, comment=%s' % (binary, comment))
    try:
        opcode = struct.unpack('<I', binary)[0]
    except:
        logging.error('cannot unpack %r' % binary)
        raise
    condition_code = CONDITION_CODES[opcode >> 28]
    if condition_code == 'undefined':
        raise(ValueError('Invalid branch instruction 0x%x' % opcode))
    mnemonic = ['B', 'BL'][(opcode >> 24) & 1]
    if (opcode >> 25) & 0b111 != 0b101:
        raise(ValueError('not a branch instruction'))
    try:
        offset = safeint(ASSEMBLED_PATTERN.match('# %s ' % comment).group(1))
    except:
        raise(ValueError('must provide offset in comment to calculate branch'))
    branch_offset = sign_extend(opcode << 2, 26) + offset + PREFETCH
    expanded = '    %s%s 0x%x  ;# %s' % (
        mnemonic, condition_code, branch_offset & MASK32, comment or '')
    sourceline = expanded.lower()
    if output:
        print sourceline
    return tokenize(sourceline)[1]

def sign_extend(value, bits):
    '''
    sign-extend 2s complement number

    http://stackoverflow.com/a/32031543/493161
    '''
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

def dump_dp_instruction(binary, comment='', output=True):
    '''
    disassemble a data processing instruction
    '''
    try:
        opcode = struct.unpack('<I', binary)[0]
    except:
        logging.error('cannot unpack %r' % binary)
        raise
    if opcode & (3 << 26):
        raise(ValueError('Unrecognized opcode 0x%x' % opcode))
    condition_code = CONDITION_CODES[opcode >> 28]
    mnemonic = DATA_PROCESSING_CODES[(opcode >> 21) & MASK4]
    if condition_code == 'undefined':
        raise(ValueError('Undefined condition code in 0x%x' % opcode))
    immediate = bool(opcode & (1 << 25))
    set_condition_codes = ['', 'S'][bool(opcode & (1 << 20))]
    operands = [named_register('R%d' % ((opcode >> 16) & MASK4))]
    destination = named_register('R%d' % ((opcode >> 12) & MASK4))
    if immediate:
        shift = (opcode >> 8) & MASK4
        operand = opcode & MASK8
        operands.append(immediate_shift(shift, operand))
    else:
        shift = (opcode >> 4) & MASK8
        operand = named_register('R%d' % (opcode & MASK4))
        operands.append(register_shift(shift, operand))
    expanded = '    %s%s%s %s, %s  ;# %s' % (
        mnemonic, condition_code, set_condition_codes,
        destination, ', '.join(operands), comment or '')
    sourceline = expanded.lower()
    if output:
        print sourceline
    return tokenize(sourceline)[1]

def register_shift(shift, operand, sign=''):
    '''
    format operand 2 with specified shift
    '''
    #logging.debug('decoding register shift 0x%x' % shift)
    shift_type = SHIFT_TYPE[(shift >> 1) & 3]
    if shift & 1:
        if shift & 8:
            raise(ValueError('Invalid bit set for register shift'))
        shift_register = named_register('R%d' % (shift >> 4))
        return '%s, %s %s%s' % (operand, shift_type, sign, shift_register)
    else:
        shift_amount = (shift >> 3)
        return '%s, %s #%s%d' % (operand, shift_type, sign, shift_amount)

def immediate_shift(shift, operand):
    '''
    format immediate operand 2 with specified 4-bit rotation
    '''
    rotate_amount = shift
    return '#%d' % ror(operand, rotate_amount)

def ror(number, amount):
    '''
    rotate 32-bit number right `amount * 2` bits

    >>> '0x%x' % ror(0x7d, 0xa)
    '0x7d000'
    '''
    #logging.debug('rotating right 0x%x by 0x%x' % (number, amount))
    mask = (2 ** 32) - 1
    rotate = amount * 2
    rotated = (number & mask) >> rotate
    rotated |= (number << (32 - rotate)) & mask
    return rotated

def packnumber(number):
    '''
    opposite of ror, the packing process
    >>> '0x%x' % packnumber(0x7d000)
    '0xa7d'
    '''
    mask = (2 ** 32) - 1
    shift = 0
    while number > 255:
        number = ((number & 3) << 30) | (number >> 2)
        shift += 1
    if shift:  # pack it as small as possible
        while not number & 3:
            number >>= 2
            shift += 1
        return number | ((16 - shift) << 8)
    else:
        return number

def safeint(string):
    trimmed = string.rstrip(',')
    return ast.literal_eval(trimmed)

def dumplong(binary, comment = ''):
    long_integer = struct.unpack('<I', binary[:4])[0]
    print('    .long {0:#x}  ;# {1:s}'.format(long_integer, comment))
    return long_integer

def dumpbytes(binary, comment = ''):
    bytevalues = [ord(b) for b in binary]
    string = ', '.join(['{0:#x}'.format(b) for b in bytevalues])
    print('    .byte {0:s}  ;# {1:s}'.format(string, comment))
    return bytevalues

def dumpascii(binary, comment = ''):
    '''
    dump out 0-padded ASCII string

    >>> dumpascii('01234567890123')
        .ascii "01234567890123"  ;# 
        .byte 0, 0
    '01234567890123'
    
    >>> dumpascii('0123456789012345')
        .ascii "0123456789012345"  ;# 
    '0123456789012345'
    '''
    string = binary[:16].rstrip('\0')
    padding = ', '.join(['0'] * (16 - len(string)))
    print '    .ascii "{0:s}"  ;# {1:s}'.format(string, comment)
    if padding:
        print '    .byte {0:s}'.format(padding)
    return string

def dumpheader(binary):
    '''
    dump out mach-o header

    from http://lowlevelbits.org/parse-mach-o-files/

    struct mach_header {
     uint32_t      magic;
     cpu_type_t    cputype;
     cpu_subtype_t cpusubtype;
     uint32_t      filetype;
     uint32_t      ncmds;
     uint32_t      sizeofcmds;
     uint32_t      flags;
    };
    '''
    offset = 0
    names = ['magic', 'cputype', 'cpusubtype', 'filetype', 'ncmds',
             'sizeofcmds', 'flags']
    for index in range(len(names)):
        value = dumplong(binary[offset:offset + 4],
                         buildcomment(binary, offset, names[index]))
        HEADER[names[index]] = value
        offset += 4
    return offset

def buildcomment(binary, offset, comment = ''):
    '''
    make an informative comment with offset and content in various forms
    '''
    chunk = binary[offset:offset + 4]
    address = ADDRESSES.get(offset, offset)
    prefix = '0x%x: ' % address
    try:
        prefix += '0x%x ' % struct.unpack('<I', chunk)[0]
    except struct.error:
        logging.debug('cannot unpack %r' % chunk)
        return comment
    prefix += '%s' % repr(chunk)
    return prefix + ' ' + comment

def dumpsegments(binary, offset):
    '''
    struct segment_command {
     uint32_t  cmd;
     uint32_t  cmdsize;
     char      segname[16];
     uint32_t  vmaddr;
     uint32_t  vmsize;
     uint32_t  fileoff;
     uint32_t  filesize;
     vm_prot_t maxprot;
     vm_prot_t initprot;
     uint32_t  nsects;
     uint32_t  flags;
    };
    '''
    names = ['cmd', 'cmdsize', 'segname', 'vmaddr', 'vmsize', 'fileoff',
             'filesize', 'maxprot', 'initprot', 'nsects', 'flags']
    for cmdindex in range(HEADER['ncmds']):
        print(';# dumping segment')
        SEGMENTS.append({})
        segment = SEGMENTS[-1]
        cmd_offset = offset
        for index in range(len(names)):
            if names[index] == 'segname':
                if segment['cmd'] == 1:
                    dumpascii(binary[offset:])
                    offset += 16
                else:  # not a segment load, just dump it raw
                    break
            else:
                value = dumplong(binary[offset:offset + 4],
                                 buildcomment(binary, offset, names[index]))
                segment[names[index]] = value
                offset += 4
        if 'nsects' in segment:
            segment['sections'] = []
            for section in range(segment['nsects']):
                print(';# dumping section %d of %d' % (
                    section, segment['nsects']))
                segment['sections'].append({})
                offset = dumpsection(binary, offset)
            for addr in range(
                segment['fileoff'], segment['fileoff'] + segment['vmsize'], 4):
                ADDRESSES[addr] = addr - segment['fileoff'] + segment['vmaddr']
        else:
            print(';# dumping remainder of command')
            while offset < cmd_offset + segment['cmdsize']:
                dumplong(binary[offset:offset + 4],
                         buildcomment(binary, offset))
                offset += 4
    return offset

def dumpsection(binary, offset):
    '''
    struct section32 {
     char name[16];
     char seg[16];
     uint32_t addr;
     uint32_t size;
     uint32_t offset;
     uint32_t align;
     uint32_t reloff;
     uint32_t nreloc;
     uint32_t flags;
     uint32_t reserve1;
     uint32_t reserve2;
    }
    '''
    names = ['name', 'seg', 'addr', 'size', 'offset', 'align',
             'reloff', 'nreloc', 'flags', 'reserve1', 'reserve2']
    section = SEGMENTS[-1]['sections'][-1]
    for index in range(len(names)):
        name = names[index]
        if name in ['name', 'seg']:
            value = dumpascii(binary[offset:offset + 16], name)
            offset += 16
        else:
            value = dumplong(binary[offset:offset + 4],
                             buildcomment(binary, offset, name))
            offset += 4
        section[name] = value
    return offset

def dumpfile(filename):
    return dump(read(filename))

def undumpfile(filename):
    return undump(readlines(filename))

def readlines(filename):
    '''
    read and return contents of file as lines, closing it properly
    '''
    infile = open(filename, 'r')
    data = [s.rstrip() for s in infile.readlines()]
    infile.close()
    return data

def read(filename):
    '''
    read and return contents of file, closing it properly
    '''
    infile = open(filename, 'rb')
    data = infile.read()
    infile.close()
    return data

if __name__ == '__main__':
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        if filename.endswith(('.as', '.asm', '.dsm')):
            undumpfile(filename)
        else:
            dumpfile(filename)
    else:
        print('No file specified, so running doctest instead.')
        import doctest
        doctest.testmod()
