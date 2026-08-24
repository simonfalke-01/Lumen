/**
 * Draw a fixed Version-11, error-correction-L QR code for a protocol-v3 URI.
 * The implementation is intentionally limited to byte-mode invitations no
 * longer than 321 UTF-8 bytes, which covers the WebUI's bounded host field.
 */
export function drawInvitationQr(canvas, text) {
  const bytes = new TextEncoder().encode(text)
  if (bytes.length > 321) throw new Error('Invitation is too long for the QR renderer')

  const data = []
  const appendBits = (value, count) => {
    for (let bit = count - 1; bit >= 0; --bit) data.push((value >>> bit) & 1)
  }
  appendBits(0x4, 4)
  appendBits(bytes.length, 16)
  bytes.forEach(byte => appendBits(byte, 8))
  for (let index = 0; index < Math.min(4, 2592 - data.length); ++index) data.push(0)
  while (data.length % 8) data.push(0)
  const dataCodewords = []
  for (let offset = 0; offset < data.length; offset += 8) {
    let value = 0
    for (let bit = 0; bit < 8; ++bit) value = (value << 1) | data[offset + bit]
    dataCodewords.push(value)
  }
  for (let pad = 0; dataCodewords.length < 324; ++pad) dataCodewords.push(pad % 2 ? 0x11 : 0xec)

  const multiply = (left, right) => {
    let result = 0
    for (let bit = 7; bit >= 0; --bit) {
      result = (result << 1) ^ ((result >>> 7) * 0x11d)
      result ^= ((right >>> bit) & 1) * left
    }
    return result
  }
  const divisor = new Array(20).fill(0)
  divisor[19] = 1
  let root = 1
  for (let index = 0; index < 20; ++index) {
    for (let coefficient = 0; coefficient < divisor.length; ++coefficient) {
      divisor[coefficient] = multiply(divisor[coefficient], root)
      if (coefficient + 1 < divisor.length) divisor[coefficient] ^= divisor[coefficient + 1]
    }
    root = multiply(root, 2)
  }
  const remainder = block => {
    const result = new Array(20).fill(0)
    block.forEach(value => {
      const factor = value ^ result.shift()
      result.push(0)
      divisor.forEach((coefficient, index) => { result[index] ^= multiply(coefficient, factor) })
    })
    return result
  }
  const blocks = []
  for (let block = 0; block < 4; ++block) blocks.push(dataCodewords.slice(block * 81, block * 81 + 81))
  const errorBlocks = blocks.map(remainder)
  const codewords = []
  for (let column = 0; column < 81; ++column) blocks.forEach(block => codewords.push(block[column]))
  for (let column = 0; column < 20; ++column) errorBlocks.forEach(block => codewords.push(block[column]))

  const size = 61
  const modules = Array.from({ length: size }, () => new Array(size).fill(false))
  const functions = Array.from({ length: size }, () => new Array(size).fill(false))
  const set = (row, column, dark, isFunction = true) => {
    if (row < 0 || row >= size || column < 0 || column >= size) return
    modules[row][column] = Boolean(dark)
    if (isFunction) functions[row][column] = true
  }
  const finder = (top, left) => {
    for (let row = -1; row <= 7; ++row) {
      for (let column = -1; column <= 7; ++column) {
        const inside = row >= 0 && row <= 6 && column >= 0 && column <= 6
        const dark = inside && (
          row === 0 || row === 6 || column === 0 || column === 6 ||
          (row >= 2 && row <= 4 && column >= 2 && column <= 4)
        )
        set(top + row, left + column, dark)
      }
    }
  }
  finder(0, 0)
  finder(0, size - 7)
  finder(size - 7, 0)
  for (let index = 8; index < size - 8; ++index) {
    set(6, index, index % 2 === 0)
    set(index, 6, index % 2 === 0)
  }
  const centers = [6, 30, 54]
  centers.forEach((row, rowIndex) => centers.forEach((column, columnIndex) => {
    if ((rowIndex === 0 && columnIndex === 0) ||
        (rowIndex === 0 && columnIndex === centers.length - 1) ||
        (rowIndex === centers.length - 1 && columnIndex === 0)) return
    for (let y = -2; y <= 2; ++y) {
      for (let x = -2; x <= 2; ++x) set(row + y, column + x, Math.max(Math.abs(x), Math.abs(y)) !== 1)
    }
  }))

  let versionRemainder = 11 << 12
  for (let bit = 17; bit >= 12; --bit) {
    if ((versionRemainder >>> bit) & 1) versionRemainder ^= 0x1f25 << (bit - 12)
  }
  const versionBits = (11 << 12) | versionRemainder
  for (let bit = 0; bit < 18; ++bit) {
    const dark = ((versionBits >>> bit) & 1) !== 0
    const a = size - 11 + (bit % 3)
    const b = Math.floor(bit / 3)
    set(b, a, dark)
    set(a, b, dark)
  }

  const reserveFormat = () => {
    for (let bit = 0; bit <= 5; ++bit) set(bit, 8, false)
    set(7, 8, false); set(8, 8, false); set(8, 7, false)
    for (let bit = 9; bit < 15; ++bit) set(8, 14 - bit, false)
    for (let bit = 0; bit < 8; ++bit) set(8, size - 1 - bit, false)
    for (let bit = 8; bit < 15; ++bit) set(size - 15 + bit, 8, false)
    set(size - 8, 8, true)
  }
  reserveFormat()

  let bitIndex = 0
  let upward = true
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) --right
    for (let vertical = 0; vertical < size; ++vertical) {
      const row = upward ? size - 1 - vertical : vertical
      for (let offset = 0; offset < 2; ++offset) {
        const column = right - offset
        if (functions[row][column]) continue
        const raw = bitIndex < codewords.length * 8
          ? (codewords[Math.floor(bitIndex / 8)] >>> (7 - (bitIndex % 8))) & 1
          : 0
        modules[row][column] = Boolean(raw ^ (((row + column) & 1) === 0))
        ++bitIndex
      }
    }
    upward = !upward
  }

  let formatRemainder = 1 << 13
  for (let bit = 14; bit >= 10; --bit) {
    if ((formatRemainder >>> bit) & 1) formatRemainder ^= 0x537 << (bit - 10)
  }
  const formatBits = (((1 << 3) | 0) << 10 | formatRemainder) ^ 0x5412
  const formatBit = bit => ((formatBits >>> bit) & 1) !== 0
  for (let bit = 0; bit <= 5; ++bit) set(bit, 8, formatBit(bit))
  set(7, 8, formatBit(6)); set(8, 8, formatBit(7)); set(8, 7, formatBit(8))
  for (let bit = 9; bit < 15; ++bit) set(8, 14 - bit, formatBit(bit))
  for (let bit = 0; bit < 8; ++bit) set(8, size - 1 - bit, formatBit(bit))
  for (let bit = 8; bit < 15; ++bit) set(size - 15 + bit, 8, formatBit(bit))
  set(size - 8, 8, true)

  const quiet = 4
  const scale = 4
  canvas.width = canvas.height = (size + quiet * 2) * scale
  const context = canvas.getContext('2d')
  context.imageSmoothingEnabled = false
  context.fillStyle = '#fff'
  context.fillRect(0, 0, canvas.width, canvas.height)
  context.fillStyle = '#000'
  modules.forEach((row, y) => row.forEach((dark, x) => {
    if (dark) context.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale)
  }))
}
