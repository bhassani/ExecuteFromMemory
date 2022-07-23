; ::::: Running Process from memory :::::
; :::::     GamingMasteR -AT4RE     :::::

.386p
.model	flat, stdcall
option	casemap: none

include		windows.inc
include		kernel32.inc
include		ntdll.inc
include		ExecuteFromMem.Inc

includelib	kernel32.lib
includelib	ntdll.lib


.data
myname	db	"ExecuteFromMem.exe",0

.data?

.code
main	proc
	LOCAL sinfo: STARTUPINFO
	LOCAL pinfo: PROCESS_INFORMATION
	LOCAL base: dword
	LOCAL sec: ptr IMAGE_SECTION_HEADER
	LOCAL cnt: CONTEXT

	invoke RtlZeroMemory, addr sinfo, sizeof STARTUPINFO
	
	; create any process in suspend mode, and out progy is the best choice of course ;)
	invoke CreateProcess, addr myname, 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, addr sinfo, addr pinfo
	
	invoke RtlZeroMemory, addr cnt, sizeof CONTEXT
	
	mov cnt.ContextFlags, CONTEXT_INTEGER
	
	; save the main thread context
	invoke GetThreadContext, pinfo.hThread, addr cnt
	
	invoke GetModuleHandle, 0
	
	; unmap all the process's sections, and since they are sequenced then they are all unmapped one time
	invoke ZwUnmapViewOfSection, pinfo.hProcess, eax
	
	mov edi, offset file
	
	add edi, IMAGE_DOS_HEADER.e_lfanew[edi]
	
	assume edi:  ptr IMAGE_NT_HEADERS
	
	; reallocate memory for the new process @ base == ImageBase and size == SizeOfImage
	invoke VirtualAllocEx, pinfo.hProcess, [edi].OptionalHeader.ImageBase, [edi].OptionalHeader.SizeOfImage, MEM_COMMIT + MEM_RESERVE, PAGE_EXECUTE_READWRITE
	
	mov base, eax
	
	; write the new process's header
	invoke WriteProcessMemory, pinfo.hProcess, base, addr file, [edi].OptionalHeader.SizeOfHeaders, 0
	
	; get the 1st section header b4 entering the loop
	lea eax, [edi].OptionalHeader
	
	mov sec, eax
	
	movzx eax, [edi].FileHeader.SizeOfOptionalHeader
	
	add sec, eax
	
	xor eax, eax
	
	xor esi, esi
	
	xor ecx, ecx
	
	.while ( si < [edi].FileHeader.NumberOfSections )
		
		imul eax, esi, sizeof IMAGE_SECTION_HEADER
		
		add eax, sec
		
		mov ebx, base
		
		add ebx, IMAGE_SECTION_HEADER.VirtualAddress[eax]
		
		mov edx, offset file
		
		add edx, IMAGE_SECTION_HEADER.PointerToRawData[eax]
		
		; write every section data
		invoke WriteProcessMemory, pinfo.hProcess, ebx, edx, IMAGE_SECTION_HEADER.SizeOfRawData[eax],0 
		
		inc esi
		
	.endw
	
	mov eax, base
	
	add eax, [edi].OptionalHeader.AddressOfEntryPoint
	
	mov cnt.regEax, eax
	
	; make the new process's main thread eax register == the new entry point
	invoke SetThreadContext, pinfo.hThread, addr cnt
	
	; fire it :p
	invoke ResumeThread, pinfo.hThread
	
	ret
main endp


end main
