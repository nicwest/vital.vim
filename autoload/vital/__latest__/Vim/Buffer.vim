let s:save_cpo = &cpo
set cpo&vim

function! s:_vital_loaded(V)
  let s:V = a:V
  let s:P = s:V.import('Prelude')
endfunction

function! s:_vital_depends()
  return ['Prelude']
endfunction

function! s:is_cmdwin()
  return bufname('%') ==# '[Command Line]'
endfunction

function! s:open(buffer, opener)
  let save_wildignore = &wildignore
  let &wildignore = ''
  try
    if s:P.is_funcref(a:opener)
      let loaded = !bufloaded(a:buffer)
      call a:opener(a:buffer)
    elseif a:buffer is 0 || a:buffer is ''
      let loaded = 1
      silent execute a:opener
      enew
    else
      let loaded = !bufloaded(a:buffer)
      if s:P.is_string(a:buffer)
        execute a:opener '`=a:buffer`'
      elseif s:P.is_number(a:buffer)
        silent execute a:opener
        execute a:buffer 'buffer'
      else
        throw 'vital: Vim.Buffer: Unknown opener type.'
      endif
    endif
  finally
    let &wildignore = save_wildignore
  endtry
  return loaded
endfunction

function! s:get_selected_text(...)
  echohl WarningMsg
  echom "[WARN] s:get_selected_text() is deprecated. Use 's:get_last_selected()'."
  echohl None
  return call('s:get_last_selected', a:000)
endfunction

" Get the last selected text in visual mode.
function! s:get_last_selected()
  let save = getreg('"', 1)
  let save_type = getregtype('"')

  try
    normal! gv""y
    return @"
  finally
    call setreg('"', save, save_type)
  endtry
endfunction


let &cpo = s:save_cpo
unlet s:save_cpo

" vim:set et ts=2 sts=2 sw=2 tw=0:
