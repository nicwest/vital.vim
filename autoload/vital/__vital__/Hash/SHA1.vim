" Utilities for SHA1

let s:save_cpo = &cpo
set cpo&vim

function! s:_vital_loaded(V) abort
  let s:V = a:V
  let s:bitwise = s:V.import('Bitwise')
endfunction

function! s:_vital_depends() abort
  return ['Bitwise']
endfunction


function! s:sum(data) abort
  " Initialize variables:
  let l:h0 = 0x67452301
  let l:h1 = 0xEFCDAB89
  let l:h2 = 0x98BADCFE
  let l:h3 = 0x10325476
  let l:h4 = 0xC3D2E1F0

  " message as bytes
  let l:message = s:_str2bytes(a:data)
  " message length in bits 
  let l:ml = len(l:message) * 8

  " Pre-processing:
  " append the bit '1' to the message
  call add(l:message, 0x80)

  " append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
  " is congruent to −64 ≡ 448 (mod 512)
  while fmod(len(l:message), 64) != 56
      call add(l:message, 0)
  endwhile

  " append ml, the original message length (in bits), as a 64-bit big-endian
  " integer.  Thus, the total length is a multiple of 512 bits.
  if has('num64')
    call extend(l:message, s:_int2bytes(64, l:ml))
  else
    call extend(l:message, [0, 0, 0, 0])
    call extend(l:message, s:_int2bytes(32, l:ml))
  endif

  " Process the message in successive 64 byte chunks (512 bit chunks):
  for l:chunk_i in range(0, len(l:message)-1, 64)
    let l:chunk = l:message[l:chunk_i : l:chunk_i + 63]

    " break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
    let l:w = map(range(16), 's:_bytes2int32(l:chunk[(v:val*4):(v:val*4)+3])')

    " Extend the sixteen 32-bit words into eighty 32-bit words:
    for l:i in range(16, 79)
      let l:w_i = (s:bitwise.xor(l:w[l:i-3], s:bitwise.xor(l:w[l:i-8], s:bitwise.xor(l:w[l:i-14], l:w[l:i-16]))))
      call add(l:w, s:_leftrotate(l:w_i, 1))
    endfor

    "Initialize hash value for this chunk:
    let l:a = l:h0
    let l:b = l:h1
    let l:c = l:h2
    let l:d = l:h3
    let l:e = l:h4
    
    " Main loop:
    for l:i in range(0, 79)
      if 0 <= l:i &&  l:i <= 19
        let l:f = s:bitwise.or(s:bitwise.and(l:b, l:c), s:bitwise.and(s:bitwise.invert(l:b), l:d))
        let l:k = 0x5A827999
      elseif 20 <= l:i && l:i <= 39
        let l:f = s:bitwise.xor(l:b, s:bitwise.xor(l:c, l:d))
        let l:k = 0x6ED9EBA1
      elseif 40 <= l:i && l:i <= 59
        let l:f = s:bitwise.or(s:bitwise.and(l:b, l:c), s:bitwise.or(s:bitwise.and(l:b, l:d), s:bitwise.and(l:c, l:d))) 
        let l:k = 0x8F1BBCDC
      elseif 60 <= l:i && l:i <= 79
        let l:f = s:bitwise.xor(l:b, s:bitwise.xor(l:c, l:d))
        let l:k = 0xCA62C1D6
      endif

      let l:temp = s:bitwise.and(s:_leftrotate(l:a, 5) + l:f + l:e + l:k + l:w[l:i], 0xffffffff)
      let l:e = l:d
      let l:d = l:c
      let l:c = s:_leftrotate(l:b, 30)
      let l:b = l:a
      let l:a = l:temp
    endfor

    " Add this chunk's hash to result so far:
    let l:h0 = s:bitwise.and(l:h0 + l:a, 0xffffffff)
    let l:h1 = s:bitwise.and(l:h1 + l:b, 0xffffffff)
    let l:h2 = s:bitwise.and(l:h2 + l:c, 0xffffffff)
    let l:h3 = s:bitwise.and(l:h3 + l:d, 0xffffffff)
    let l:h4 = s:bitwise.and(l:h4 + l:e, 0xffffffff)

  endfor

  let l:bytes = []
  call extend(l:bytes, s:_int2bytes(32, l:h0))
  call extend(l:bytes, s:_int2bytes(32, l:h1))
  call extend(l:bytes, s:_int2bytes(32, l:h2))
  call extend(l:bytes, s:_int2bytes(32, l:h3))
  call extend(l:bytes, s:_int2bytes(32, l:h4))

  return s:_bytes2str(l:bytes)
endfunction

function! s:_leftrotate(x, c) abort
  let l:x = s:bitwise.and(a:x, 0xFFFFFFFF)
  return s:bitwise.and(s:bitwise.or(s:bitwise.lshift(l:x, a:c), s:bitwise.rshift(l:x, (32-a:c))), 0xFFFFFFFF)
endfunction

function! s:_bytes2str(bytes) abort
  return join(map(a:bytes, 'printf(''%02x'', v:val)'), '')
endfunction

function! s:_str2bytes(str) abort
  return map(range(len(a:str)), 'char2nr(a:str[v:val])')
endfunction

function! s:_int2bytes(bits, int) abort
  let l:bytes = a:bits / 8
  return map(range(l:bytes), 's:bitwise.and(s:bitwise.rshift(a:int, (l:bytes - v:val - 1)  * 8), 0xff)')
endfunction

function! s:_bytes2int32(bytes) abort
  return  s:bitwise.or(s:bitwise.lshift(a:bytes[0], 24), 
        \ s:bitwise.or(s:bitwise.lshift(a:bytes[1], 16),
        \ s:bitwise.or(s:bitwise.lshift(a:bytes[2], 8),
        \ a:bytes[3])))
endfunction

let &cpo = s:save_cpo
unlet s:save_cpo

" vim:set et ts=2 sts=2 sw=2 tw=0:
