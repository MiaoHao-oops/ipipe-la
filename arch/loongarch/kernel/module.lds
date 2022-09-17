SECTIONS {
	. = ALIGN(4);
	.ftrace_tramp : {
		LONG(0); LONG(0); LONG(0); LONG(0);
		LONG(0); LONG(0); LONG(0); LONG(0);
	}
}
