// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";

const registerName = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const registerIndex = Object.freeze({ eax: 0, ecx: 1, edx: 2, ebx: 3, esp: 4, ebp: 5, esi: 6, edi: 7 });
const maxStackSizeByte = 16 * 1024 * 1024;
const stackPageSizeByte = 0x1000;
const returnSentinelCandidate = [0xfffff000, 0x20000000, 0x10000000, 0x80000000, 0x90000000];
const flagMask = Object.freeze({ carry: 1, parity: 4, adjust: 0x10, zero: 0x40, sign: 0x80, overflow: 0x800 });

class RuntimeFault extends Error {
  constructor(code, message, detail = {}) {
    super(message);
    this.name = "RuntimeFault";
    this.code = code;
    Object.assign(this, detail);
  }
}

function unsigned(value) {
  return value >>> 0;
}

function signed(value) {
  return value | 0;
}

function signExtend(value, bitCount) {
  const shiftCount = 32 - bitCount;
  return (value << shiftCount) >> shiftCount;
}

function maskValue(value, sizeByte) {
  if (sizeByte === 1) return value & 0xff;
  if (sizeByte === 2) return value & 0xffff;
  return value >>> 0;
}

function parity(value) {
  let bit = value & 0xff;
  bit ^= bit >>> 4;
  bit ^= bit >>> 2;
  bit ^= bit >>> 1;
  return (bit & 1) === 0;
}

function chooseStackBase(imageStart, imageEnd, stackSizeByte) {
  const stackBaseValue = [0x70000000, 0x60000000, 0x50000000, 0x40000000, 0x30000000];
  for (const currentBase of stackBaseValue) {
    const currentEnd = currentBase + stackSizeByte;
    if (currentEnd <= 0x100000000 && (currentEnd <= imageStart || currentBase >= imageEnd)) return currentBase;
  }
  throw new RuntimeFault("memory_fault", "No bounded stack range is available", { address: null });
}

function chooseReturnSentinel(imageStart, imageEnd, stackBase, stackEnd) {
  for (const candidate of returnSentinelCandidate) {
    const isImageAddress = candidate >= imageStart && candidate < imageEnd;
    const isStackAddress = candidate >= stackBase && candidate < stackEnd;
    if (!isImageAddress && !isStackAddress) return candidate;
  }
  throw new RuntimeFault("memory_fault", "No reserved return sentinel is available", { address: null });
}

function normalizeStackSize(value) {
  const reserveByte = Number.isSafeInteger(value) && value > 0 ? value : 0x10000;
  return Math.max(stackPageSizeByte, Math.min(maxStackSizeByte, Math.ceil(reserveByte / stackPageSizeByte) * stackPageSizeByte));
}

function flagValue(flag) {
  let value = 0x2;
  for (const [name, mask] of Object.entries(flagMask)) if (flag[name]) value |= mask;
  return value >>> 0;
}

function createRegisterReport(registerValue, instructionPointer) {
  const register = {};
  for (let index = 0; index < registerName.length; index += 1) register[registerName[index]] = registerValue[index] >>> 0;
  register.eip = instructionPointer >>> 0;
  return register;
}

function createFlagReport(flag, eflagsValue) {
  return {
    carry: Boolean(flag.carry),
    parity: Boolean(flag.parity),
    adjust: Boolean(flag.adjust),
    zero: Boolean(flag.zero),
    sign: Boolean(flag.sign),
    overflow: Boolean(flag.overflow),
    eflags: eflagsValue >>> 0,
  };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function faultValue(fault) {
  const exception = { code: fault.code, type: fault.code, message: fault.message };
  for (const name of ["address", "opcode", "size_byte", "target"]) {
    if (fault[name] !== undefined) exception[name] = fault[name];
  }
  return exception;
}

function conditionValue(condition, flag) {
  switch (condition & 0x0f) {
    case 0x0: return flag.overflow;
    case 0x1: return !flag.overflow;
    case 0x2: return flag.carry;
    case 0x3: return !flag.carry;
    case 0x4: return flag.zero;
    case 0x5: return !flag.zero;
    case 0x6: return flag.carry || flag.zero;
    case 0x7: return !flag.carry && !flag.zero;
    case 0x8: return flag.sign;
    case 0x9: return !flag.sign;
    case 0xa: return flag.parity;
    case 0xb: return !flag.parity;
    case 0xc: return flag.sign !== flag.overflow;
    case 0xd: return flag.sign === flag.overflow;
    case 0xe: return flag.zero || flag.sign !== flag.overflow;
    case 0xf: return !flag.zero && flag.sign === flag.overflow;
    default: return false;
  }
}

function executeProbe(mapped, instructionBudgetCount) {
  const { report, image, section } = mapped;
  const imageStart = report.load_base;
  const imageEnd = imageStart + image.length;
  const stackSizeByte = normalizeStackSize(report.stack_reserve_byte);
  const stackBase = chooseStackBase(imageStart, imageEnd, stackSizeByte);
  const stackEnd = stackBase + stackSizeByte;
  const returnSentinel = chooseReturnSentinel(imageStart, imageEnd, stackBase, stackEnd);
  const stack = Buffer.alloc(stackSizeByte);
  const registerValue = new Uint32Array(8);
  const flag = { carry: false, parity: false, adjust: false, zero: false, sign: false, overflow: false };
  const traceHash = createHash("sha256");
  const initialStackPointer = stackEnd - 4;
  let instructionPointer = report.entry_address >>> 0;
  let instructionCount = 0;
  let stopReason = null;
  let exception = null;
  let instructionByte = null;
  let memoryUndo = null;

  registerValue[registerIndex.esp] = initialStackPointer >>> 0;

  function checkRange(address, sizeByte, code, mode) {
    const addressValue = unsigned(address);
    if (!Number.isInteger(sizeByte) || sizeByte <= 0 || addressValue + sizeByte > 0x100000000) {
      throw new RuntimeFault(code, `${mode} address is outside the 32-bit address space`, { address: addressValue, size_byte: sizeByte });
    }
    if (addressValue >= imageStart && addressValue + sizeByte <= imageEnd) {
      let offset = addressValue - imageStart;
      const end = offset + sizeByte;
      while (offset < end) {
        const currentSection = section.find((entry) => offset >= entry.virtual_address && offset < entry.virtual_address + entry.mapped_size_byte);
        if (!currentSection) {
          if (mode !== "read") throw new RuntimeFault(`${mode}_fault`, `${mode} touches unmapped image bytes`, { address: addressValue, size_byte: sizeByte });
          offset += 1;
          continue;
        }
        const sectionEnd = Math.min(end, currentSection.virtual_address + currentSection.mapped_size_byte);
        const isReadable = (currentSection.characteristic & 0x40000000) !== 0 || (currentSection.characteristic & 0x20000000) !== 0;
        const isWritable = (currentSection.characteristic & 0x80000000) !== 0;
        const isExecutable = (currentSection.characteristic & 0x20000000) !== 0;
        if (mode === "fetch" && !isExecutable) throw new RuntimeFault("fetch_fault", "Instruction fetch is not executable", { address: addressValue, size_byte: sizeByte });
        if (mode === "read" && !isReadable) throw new RuntimeFault("read_fault", "Image bytes are not readable", { address: addressValue, size_byte: sizeByte });
        if (mode === "write" && !isWritable) throw new RuntimeFault("write_fault", "Image bytes are not writable", { address: addressValue, size_byte: sizeByte });
        offset = sectionEnd;
      }
      return { kind: "image", offset: addressValue - imageStart };
    }
    if (addressValue >= stackBase && addressValue + sizeByte <= stackEnd) {
      if (mode === "fetch") throw new RuntimeFault("fetch_fault", "Stack memory is not executable", { address: addressValue, size_byte: sizeByte });
      return { kind: "stack", offset: addressValue - stackBase };
    }
    throw new RuntimeFault(`${mode}_fault`, `${mode} address is outside mapped image and bounded stack`, { address: addressValue, size_byte: sizeByte });
  }

  function readMemory(address, sizeByte, mode = "read") {
    const location = checkRange(address, sizeByte, `${mode}_fault`, mode);
    const value = location.kind === "image" ? image : stack;
    if (sizeByte === 1) return value[location.offset];
    if (sizeByte === 2) return value.readUInt16LE(location.offset);
    if (sizeByte === 4) return value.readUInt32LE(location.offset);
    throw new RuntimeFault("read_fault", "Only byte, word, and dword accesses are supported", { address: unsigned(address), size_byte: sizeByte });
  }

  function writeMemory(address, sizeByte, value) {
    const location = checkRange(address, sizeByte, "write_fault", "write");
    const target = location.kind === "image" ? image : stack;
    if (memoryUndo !== null) {
      memoryUndo.push({ target, offset: location.offset, value: Buffer.from(target.subarray(location.offset, location.offset + sizeByte)) });
    }
    if (sizeByte === 1) target[location.offset] = value & 0xff;
    else if (sizeByte === 2) target.writeUInt16LE(value & 0xffff, location.offset);
    else if (sizeByte === 4) target.writeUInt32LE(value >>> 0, location.offset);
    else throw new RuntimeFault("write_fault", "Only byte, word, and dword accesses are supported", { address: unsigned(address), size_byte: sizeByte });
  }

  function push(value) {
    const nextStackPointer = unsigned(registerValue[registerIndex.esp] - 4);
    writeMemory(nextStackPointer, 4, value);
    registerValue[registerIndex.esp] = nextStackPointer;
  }

  function pop() {
    const stackPointer = registerValue[registerIndex.esp] >>> 0;
    const value = readMemory(stackPointer, 4);
    registerValue[registerIndex.esp] = unsigned(stackPointer + 4);
    return value >>> 0;
  }

  function getRegister(index, sizeByte = 4) {
    const register = index & 7;
    const value = registerValue[register] >>> 0;
    if (sizeByte === 1) {
      if (register < 4) return value & 0xff;
      return (registerValue[register - 4] >>> 8) & 0xff;
    }
    if (sizeByte === 2) return value & 0xffff;
    return value;
  }

  function setRegister(index, value, sizeByte = 4) {
    const register = index & 7;
    if (sizeByte === 1) {
      if (register < 4) registerValue[register] = (registerValue[register] & 0xffffff00) | (value & 0xff);
      else {
        const target = register - 4;
        registerValue[target] = (registerValue[target] & 0xffff00ff) | ((value & 0xff) << 8);
      }
    } else if (sizeByte === 2) registerValue[register] = (registerValue[register] & 0xffff0000) | (value & 0xffff);
    else registerValue[register] = value >>> 0;
  }

  function fetchByte() {
    const value = readMemory(instructionPointer, 1, "fetch");
    instructionPointer = unsigned(instructionPointer + 1);
    if (instructionByte !== null) instructionByte.push(value);
    return value;
  }

  function fetchWord() {
    const low = fetchByte();
    return low | (fetchByte() << 8);
  }

  function fetchDword() {
    return (fetchByte() | (fetchByte() << 8) | (fetchByte() << 16) | (fetchByte() << 24)) >>> 0;
  }

  function decodeModrm(operandSizeByte) {
    const value = fetchByte();
    const mode = value >>> 6;
    const reg = (value >>> 3) & 7;
    const rm = value & 7;
    if (mode === 3) return { mode, reg, rm, is_register: true, address: null, size_byte: operandSizeByte };
    let address = 0;
    if (rm === 4) {
      const sib = fetchByte();
      const scale = 1 << (sib >>> 6);
      const index = (sib >>> 3) & 7;
      const base = sib & 7;
      if (index !== 4) address += getRegister(index) * scale;
      if (mode === 0 && base === 5) address += fetchDword();
      else address += getRegister(base);
    } else if (mode === 0 && rm === 5) address = fetchDword();
    else address = getRegister(rm);
    if (mode === 1) address += signExtend(fetchByte(), 8);
    else if (mode === 2) address += fetchDword();
    return { mode, reg, rm, is_register: false, address: unsigned(address), size_byte: operandSizeByte };
  }

  function operandRead(decoded, sizeByte = decoded.size_byte) {
    return decoded.is_register ? getRegister(decoded.rm, sizeByte) : readMemory(decoded.address, sizeByte);
  }

  function operandWrite(decoded, value, sizeByte = decoded.size_byte) {
    if (decoded.is_register) setRegister(decoded.rm, value, sizeByte);
    else writeMemory(decoded.address, sizeByte, value);
  }

  function setLogicFlag(value, sizeByte) {
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const result = maskValue(value, sizeByte);
    flag.carry = false;
    flag.overflow = false;
    flag.adjust = false;
    flag.zero = result === 0;
    flag.sign = (result & (sizeByte === 1 ? 0x80 : sizeByte === 2 ? 0x8000 : 0x80000000)) !== 0;
    flag.parity = parity(result);
  }

  function setAddFlag(left, right, carryValue, result, sizeByte) {
    const bitCount = sizeByte * 8;
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const leftValue = maskValue(left, sizeByte);
    const rightValue = maskValue(right, sizeByte);
    const resultValue = maskValue(result, sizeByte);
    const sum = leftValue + rightValue + carryValue;
    flag.carry = sum > mask;
    flag.adjust = ((leftValue ^ rightValue ^ resultValue) & 0x10) !== 0;
    flag.zero = resultValue === 0;
    flag.sign = (resultValue & (1 << (bitCount - 1))) !== 0;
    flag.overflow = ((~(leftValue ^ rightValue) & (leftValue ^ resultValue) & (1 << (bitCount - 1))) !== 0);
    flag.parity = parity(resultValue);
  }

  function setSubFlag(left, right, borrowValue, result, sizeByte) {
    const bitCount = sizeByte * 8;
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const leftValue = maskValue(left, sizeByte);
    const rightValue = maskValue(right, sizeByte);
    const resultValue = maskValue(result, sizeByte);
    flag.carry = leftValue < rightValue + borrowValue;
    flag.adjust = ((leftValue ^ rightValue ^ resultValue) & 0x10) !== 0;
    flag.zero = resultValue === 0;
    flag.sign = (resultValue & (1 << (bitCount - 1))) !== 0;
    flag.overflow = (((leftValue ^ rightValue) & (leftValue ^ resultValue) & (1 << (bitCount - 1))) !== 0);
    flag.parity = parity(resultValue);
  }

  function arithmetic(kind, left, right, sizeByte, writeValue = true) {
    const mask = sizeByte === 1 ? 0xff : sizeByte === 2 ? 0xffff : 0xffffffff;
    const leftValue = maskValue(left, sizeByte);
    const rightValue = maskValue(right, sizeByte);
    let result;
    if (kind === "add" || kind === "adc") {
      const carryValue = kind === "adc" && flag.carry ? 1 : 0;
      result = unsigned(leftValue + rightValue + carryValue) & mask;
      setAddFlag(leftValue, rightValue, carryValue, result, sizeByte);
    } else if (kind === "sub" || kind === "cmp" || kind === "sbb") {
      const borrowValue = kind === "sbb" && flag.carry ? 1 : 0;
      result = unsigned(leftValue - rightValue - borrowValue) & mask;
      setSubFlag(leftValue, rightValue, borrowValue, result, sizeByte);
    } else if (kind === "and" || kind === "test") {
      result = leftValue & rightValue;
      setLogicFlag(result, sizeByte);
    } else if (kind === "or") {
      result = leftValue | rightValue;
      setLogicFlag(result, sizeByte);
    } else if (kind === "xor") {
      result = leftValue ^ rightValue;
      setLogicFlag(result, sizeByte);
    } else throw new RuntimeFault("unsupported_opcode", `Unsupported arithmetic operation ${kind}`);
    return writeValue && kind !== "cmp" && kind !== "test" ? result >>> 0 : result >>> 0;
  }

  function executeInstruction(opcode, operandSizeByte) {
    if (opcode === 0x90) return;
    if (opcode >= 0xb8 && opcode <= 0xbf) {
      const immediate = operandSizeByte === 2 ? fetchWord() : fetchDword();
      setRegister(opcode - 0xb8, immediate, operandSizeByte);
      return;
    }
    if (opcode >= 0xb0 && opcode <= 0xb7) {
      setRegister(opcode - 0xb0, fetchByte(), 1);
      return;
    }
    if (opcode >= 0x50 && opcode <= 0x57) {
      push(getRegister(opcode - 0x50, operandSizeByte));
      return;
    }
    if (opcode >= 0x58 && opcode <= 0x5f) {
      setRegister(opcode - 0x58, pop(), operandSizeByte);
      return;
    }
    if (opcode >= 0x40 && opcode <= 0x47) {
      const target = opcode - 0x40;
      const left = getRegister(target, operandSizeByte);
      const carryValue = flag.carry;
      const result = arithmetic("add", left, 1, operandSizeByte);
      setRegister(target, result, operandSizeByte);
      flag.carry = carryValue;
      return;
    }
    if (opcode >= 0x48 && opcode <= 0x4f) {
      const target = opcode - 0x48;
      const left = getRegister(target, operandSizeByte);
      const carryValue = flag.carry;
      const result = arithmetic("sub", left, 1, operandSizeByte);
      setRegister(target, result, operandSizeByte);
      flag.carry = carryValue;
      return;
    }
    if (opcode >= 0x70 && opcode <= 0x7f) {
      const displacement = signExtend(fetchByte(), 8);
      if (conditionValue(opcode & 0x0f, flag)) instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode >= 0x91 && opcode <= 0x97) {
      const target = opcode - 0x90;
      const old = registerValue[registerIndex.eax];
      registerValue[registerIndex.eax] = registerValue[target];
      registerValue[target] = old;
      return;
    }
    if (opcode === 0x68) {
      push(operandSizeByte === 2 ? fetchWord() : fetchDword());
      return;
    }
    if (opcode === 0x6a) {
      push(signExtend(fetchByte(), 8));
      return;
    }
    if (opcode === 0x9c) {
      push(flagValue(flag));
      return;
    }
    if (opcode === 0x9d) {
      const value = pop();
      flag.carry = (value & flagMask.carry) !== 0;
      flag.parity = (value & flagMask.parity) !== 0;
      flag.adjust = (value & flagMask.adjust) !== 0;
      flag.zero = (value & flagMask.zero) !== 0;
      flag.sign = (value & flagMask.sign) !== 0;
      flag.overflow = (value & flagMask.overflow) !== 0;
      return;
    }
    if (opcode === 0xe8) {
      const displacement = signed(fetchDword());
      push(instructionPointer);
      instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode === 0xe9) {
      const displacement = signed(fetchDword());
      instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode === 0xeb) {
      const displacement = signExtend(fetchByte(), 8);
      instructionPointer = unsigned(instructionPointer + displacement);
      return;
    }
    if (opcode === 0xc3) {
      const target = pop();
      instructionPointer = target;
      if (target === returnSentinel) stopReason = "entry_return";
      return;
    }
    if (opcode === 0xc2) {
      const amount = fetchWord();
      const target = pop();
      registerValue[registerIndex.esp] = unsigned(registerValue[registerIndex.esp] + amount);
      instructionPointer = target;
      if (target === returnSentinel) stopReason = "entry_return";
      return;
    }
    if (opcode === 0xc9) {
      registerValue[registerIndex.esp] = registerValue[registerIndex.ebp];
      registerValue[registerIndex.ebp] = pop();
      return;
    }
    if (opcode === 0x0f) {
      const extension = fetchByte();
      if (extension >= 0x80 && extension <= 0x8f) {
        const displacement = signed(fetchDword());
        if (conditionValue(extension & 0x0f, flag)) instructionPointer = unsigned(instructionPointer + displacement);
        return;
      }
      if (extension === 0xb6 || extension === 0xb7 || extension === 0xbe || extension === 0xbf) {
        const decoded = decodeModrm(extension === 0xb7 || extension === 0xbf ? 2 : 1);
        const value = operandRead(decoded, extension === 0xb7 || extension === 0xbf ? 2 : 1);
        const isSigned = extension === 0xbe || extension === 0xbf;
        setRegister(decoded.reg, isSigned ? signExtend(value, decoded.size_byte * 8) : value, operandSizeByte);
        return;
      }
      throw new RuntimeFault("unsupported_opcode", `Unsupported 0x0f opcode 0x${extension.toString(16)}`, { opcode: (0x0f00 | extension) >>> 0 });
    }
    if (opcode === 0x89 || opcode === 0x8b || opcode === 0x8d || opcode === 0x01 || opcode === 0x03 || opcode === 0x09 || opcode === 0x0b || opcode === 0x11 || opcode === 0x13 || opcode === 0x19 || opcode === 0x1b || opcode === 0x21 || opcode === 0x23 || opcode === 0x29 || opcode === 0x2b || opcode === 0x31 || opcode === 0x33 || opcode === 0x39 || opcode === 0x3b || opcode === 0x85 || opcode === 0x84) {
      const isByte = opcode === 0x84;
      const sizeByte = isByte ? 1 : operandSizeByte;
      const decoded = decodeModrm(sizeByte);
      if (opcode === 0x89) {
        operandWrite(decoded, getRegister(decoded.reg, operandSizeByte), operandSizeByte);
        return;
      }
      if (opcode === 0x8b) {
        setRegister(decoded.reg, operandRead(decoded, operandSizeByte), operandSizeByte);
        return;
      }
      if (opcode === 0x8d) {
        if (decoded.is_register) throw new RuntimeFault("unsupported_opcode", "LEA requires a memory operand");
        setRegister(decoded.reg, decoded.address, operandSizeByte);
        return;
      }
      const left = opcode === 0x01 || opcode === 0x09 || opcode === 0x11 || opcode === 0x19 || opcode === 0x21 || opcode === 0x29 || opcode === 0x31 || opcode === 0x85 || opcode === 0x84
        ? operandRead(decoded, sizeByte) : getRegister(decoded.reg, sizeByte);
      const right = opcode === 0x01 || opcode === 0x09 || opcode === 0x11 || opcode === 0x19 || opcode === 0x21 || opcode === 0x29 || opcode === 0x31 || opcode === 0x85 || opcode === 0x84
        ? getRegister(decoded.reg, sizeByte) : operandRead(decoded, sizeByte);
      const kind = opcode === 0x01 || opcode === 0x03 ? "add" : opcode === 0x09 || opcode === 0x0b ? "or" : opcode === 0x11 || opcode === 0x13 ? "adc" : opcode === 0x19 || opcode === 0x1b ? "sbb" : opcode === 0x21 || opcode === 0x23 ? "and" : opcode === 0x29 || opcode === 0x2b ? "sub" : opcode === 0x31 || opcode === 0x33 ? "xor" : opcode === 0x39 || opcode === 0x3b ? "cmp" : "test";
      const result = arithmetic(kind, left, right, sizeByte, kind !== "cmp" && kind !== "test");
      if (kind !== "cmp" && kind !== "test") {
        if (opcode === 0x01 || opcode === 0x09 || opcode === 0x11 || opcode === 0x19 || opcode === 0x21 || opcode === 0x29 || opcode === 0x31) operandWrite(decoded, result, sizeByte);
        else setRegister(decoded.reg, result, sizeByte);
      }
      return;
    }
    if (opcode === 0x05 || opcode === 0x0d || opcode === 0x15 || opcode === 0x1d || opcode === 0x25 || opcode === 0x2d || opcode === 0x35 || opcode === 0x3d) {
      const immediate = operandSizeByte === 2 ? fetchWord() : fetchDword();
      const kind = opcode === 0x05 ? "add" : opcode === 0x0d ? "or" : opcode === 0x15 ? "adc" : opcode === 0x1d ? "sbb" : opcode === 0x25 ? "and" : opcode === 0x2d ? "sub" : opcode === 0x35 ? "xor" : "cmp";
      const result = arithmetic(kind, registerValue[registerIndex.eax], immediate, operandSizeByte, kind !== "cmp");
      if (kind !== "cmp") setRegister(registerIndex.eax, result, operandSizeByte);
      return;
    }
    if (opcode === 0x81 || opcode === 0x83 || opcode === 0xf7 || opcode === 0xff || opcode === 0xc7 || opcode === 0xc6) {
      const isByte = opcode === 0xc6;
      const sizeByte = isByte ? 1 : operandSizeByte;
      const decoded = decodeModrm(sizeByte);
      const operation = decoded.reg;
      if (opcode === 0xc7 || opcode === 0xc6) {
        if (operation !== 0) throw new RuntimeFault("unsupported_opcode", "Unsupported MOV immediate group operation");
        const immediate = sizeByte === 1 ? fetchByte() : sizeByte === 2 ? fetchWord() : fetchDword();
        operandWrite(decoded, immediate, sizeByte);
        return;
      }
      if (opcode === 0xff) {
        if (operation === 2) {
          const target = operandRead(decoded, 4);
          push(instructionPointer);
          instructionPointer = target;
          return;
        }
        if (operation === 4) {
          instructionPointer = operandRead(decoded, 4);
          return;
        }
        if (operation === 6) {
          push(operandRead(decoded, 4));
          return;
        }
        if (operation === 0 || operation === 1) {
          const left = operandRead(decoded, operandSizeByte);
          const carryValue = flag.carry;
          const result = arithmetic(operation === 0 ? "add" : "sub", left, 1, operandSizeByte);
          operandWrite(decoded, result, operandSizeByte);
          flag.carry = carryValue;
          return;
        }
        throw new RuntimeFault("unsupported_opcode", `Unsupported 0xff group operation ${operation}`);
      }
      if (opcode === 0xf7) {
        if (operation === 0) {
          const immediate = operandSizeByte === 2 ? fetchWord() : fetchDword();
          arithmetic("test", operandRead(decoded, operandSizeByte), immediate, operandSizeByte, false);
          return;
        }
        if (operation === 2) {
          const value = operandRead(decoded, operandSizeByte);
          operandWrite(decoded, ~value, operandSizeByte);
          return;
        }
        if (operation === 3) {
          const value = operandRead(decoded, operandSizeByte);
          const result = arithmetic("sub", 0, value, operandSizeByte);
          operandWrite(decoded, result, operandSizeByte);
          return;
        }
        throw new RuntimeFault("unsupported_opcode", `Unsupported 0xf7 group operation ${operation}`);
      }
      const immediate = opcode === 0x83 ? signExtend(fetchByte(), 8) : operandSizeByte === 2 ? signExtend(fetchWord(), 16) : fetchDword();
      const kind = operation === 0 ? "add" : operation === 1 ? "or" : operation === 2 ? "adc" : operation === 3 ? "sbb" : operation === 4 ? "and" : operation === 5 ? "sub" : operation === 6 ? "xor" : "cmp";
      const result = arithmetic(kind, operandRead(decoded, operandSizeByte), immediate, operandSizeByte, kind !== "cmp");
      if (kind !== "cmp") operandWrite(decoded, result, operandSizeByte);
      return;
    }
    if (opcode === 0xa1 || opcode === 0xa3) {
      const address = fetchDword();
      if (opcode === 0xa1) setRegister(registerIndex.eax, readMemory(address, operandSizeByte), operandSizeByte);
      else writeMemory(address, operandSizeByte, getRegister(registerIndex.eax, operandSizeByte));
      return;
    }
    if (opcode === 0xc8) {
      const frameSize = fetchWord();
      const nesting = fetchByte();
      if (nesting !== 0) throw new RuntimeFault("unsupported_opcode", "ENTER nesting is not supported");
      push(registerValue[registerIndex.ebp]);
      registerValue[registerIndex.ebp] = registerValue[registerIndex.esp];
      registerValue[registerIndex.esp] = unsigned(registerValue[registerIndex.esp] - frameSize);
      return;
    }
    if (opcode >= 0xd8 && opcode <= 0xdf) throw new RuntimeFault("unsupported_opcode", "x87/FPU instructions are outside i386_probe_v1", { opcode });
    throw new RuntimeFault("unsupported_opcode", `Unsupported opcode 0x${opcode.toString(16).padStart(2, "0")}`, { opcode });
  }

  try {
    push(returnSentinel);
  } catch (fault) {
    stopReason = fault instanceof RuntimeFault ? fault.code : "memory_fault";
    exception = faultValue(fault instanceof RuntimeFault ? fault : new RuntimeFault("memory_fault", String(fault)));
  }

  while (stopReason === null && instructionCount < instructionBudgetCount) {
    const startPointer = instructionPointer;
    const registerUndo = new Uint32Array(registerValue);
    const flagUndo = { ...flag };
    memoryUndo = [];
    instructionByte = [];
    let opcode;
    try {
      opcode = fetchByte();
      instructionCount += 1;
      let operandSizeByte = 4;
      while (opcode === 0x66 || opcode === 0x67 || opcode === 0xf2 || opcode === 0xf3) {
        if (opcode === 0x66) throw new RuntimeFault("unsupported_opcode", "Operand-size override is outside the bounded 32-bit probe", { opcode });
        else if (opcode === 0x67) throw new RuntimeFault("unsupported_opcode", "Address-size override is outside the bounded 32-bit probe", { opcode });
        else throw new RuntimeFault("unsupported_opcode", "String and repeat prefixes are outside the bounded probe", { opcode });
        opcode = fetchByte();
      }
      executeInstruction(opcode, operandSizeByte);
    } catch (fault) {
      const currentFault = fault instanceof RuntimeFault ? fault : new RuntimeFault("runtime_fault", fault instanceof Error ? fault.message : String(fault));
      registerValue.set(registerUndo);
      Object.assign(flag, flagUndo);
      instructionPointer = startPointer;
      for (let index = memoryUndo.length - 1; index >= 0; index -= 1) {
        const undo = memoryUndo[index];
        undo.target.set(undo.value, undo.offset);
      }
      stopReason = currentFault.code;
      exception = faultValue(currentFault);
      exception.instruction_address = startPointer >>> 0;
      exception.eip = startPointer >>> 0;
    } finally {
      const traceValue = Buffer.alloc(4 + instructionByte.length);
      traceValue.writeUInt32LE(startPointer >>> 0, 0);
      Buffer.from(instructionByte).copy(traceValue, 4);
      traceHash.update(traceValue);
      instructionByte = null;
      memoryUndo = null;
    }
  }

  if (stopReason === null && instructionCount >= instructionBudgetCount) stopReason = "instruction_budget_exhausted";
  const memory = Buffer.concat([image, stack]);
  const eflagsValue = flagValue(flag);
  const register = createRegisterReport(registerValue, instructionPointer);
  const flagReport = createFlagReport(flag, eflagsValue);
  return {
    state: "probe_executed",
    execution_profile: "i386_probe_v1",
    register,
    flag: flagReport,
    exception,
    instruction_count: instructionCount,
    trace_sha256: traceHash.digest("hex"),
    memory_sha256: sha256(memory),
    stop_reason: stopReason,
    is_executed: instructionCount > 0 || stopReason === "entry_return",
    runtime_blocker: [],
    blocker: report.resolution_blocker,
  };
}

export function refuseI386Execution(mapped, reason, message) {
  const { report, image } = mapped;
  return {
    state: "probe_blocked",
    execution_profile: "i386_probe_v1",
    register: null,
    flag: null,
    exception: { code: reason, type: reason, message },
    instruction_count: 0,
    trace_sha256: sha256(Buffer.alloc(0)),
    memory_sha256: sha256(image),
    stop_reason: reason,
    is_executed: false,
    runtime_blocker: [message],
    blocker: [...report.resolution_blocker, message],
  };
}

export { executeProbe };
