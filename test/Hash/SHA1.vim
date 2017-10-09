let s:suite = themis#suite('Hash.SHA1')
let s:assert = themis#helper('assert')

function! s:suite.before()
  let s:SHA1 = vital#vital#new().import('Hash.SHA1')
endfunction

function! s:suite.after()
  unlet! s:SHA1
endfunction

" tests from https://tools.ietf.org/html/rfc3174#page-18
function! s:suite.encode() abort
   call s:assert.equal(s:SHA1.sum(''), 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
   call s:assert.equal(s:SHA1.sum('a'), '86f7e437faa5a7fce15d1ddcb9eaeaea377667b8')
   call s:assert.equal(s:SHA1.sum('abc'), 'a9993e364706816aba3e25717850c26c9cd0d89d')
   call s:assert.equal(s:SHA1.sum('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'), '84983e441c3bd26ebaae4aa1f95129e5e54670f1')
   call s:assert.equal(s:SHA1.sum('0123456701234567012345670123456701234567012345670123456701234567'), 'e0c094e867ef46c350ef54a7f59dd60bed92ae83')
   call s:assert.equal(s:SHA1.sum('the quick brown fox jumps over the lazy dog'), '16312751ef9307c3fd1afbcb993cdc80464ba0f1')
endfunction
