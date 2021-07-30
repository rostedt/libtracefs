%{
/* code here */

#include <stdarg.h>
#include "sqlhist-parse.h"

extern int my_yyinput(char *buf, int max);

#undef YY_INPUT
#define YY_INPUT(b, r, m) ({r = my_yyinput(b, m);})

#define YY_NO_INPUT
#define YY_NO_UNPUT

#define YY_EXTRA_TYPE struct sqlhist_bison *

#define HANDLE_COLUMN do { sb->line_idx += strlen(yytext); } while (0)

%}

%option caseless

field		[a-z_][a-z0-9_\.]*
qstring		\"[^\"]*\"
hexnum		0x[0-9a-f]+
number		[0-9a-f]+

%%

select { HANDLE_COLUMN; return SELECT; }
as { HANDLE_COLUMN; return AS; }
from { HANDLE_COLUMN; return FROM; }
join { HANDLE_COLUMN; return JOIN; }
on { HANDLE_COLUMN; return ON; }
where { HANDLE_COLUMN; return WHERE; }

{qstring} {
	HANDLE_COLUMN;
	yylval.string = store_str(sb, yytext);
	return STRING;
}

{field} {
	HANDLE_COLUMN;
	yylval.string = store_str(sb, yytext);
	return FIELD;
}

{hexnum} {
	HANDLE_COLUMN;
	yylval.number = strtol(yytext, NULL, 0);
	return NUMBER;
}

{number} {
	HANDLE_COLUMN;
	yylval.number = strtol(yytext, NULL, 0);
	return NUMBER;
}

\!= { HANDLE_COLUMN; return NEQ; }
\<= { HANDLE_COLUMN; return LE; }
\>= { HANDLE_COLUMN; return GE; }
== { HANDLE_COLUMN; return EQ; }
&& { HANDLE_COLUMN; return AND; }
"||" { HANDLE_COLUMN; return OR; }
[<>&~] { HANDLE_COLUMN; return yytext[0]; }

[\!()\-\+\*/,=] { HANDLE_COLUMN; return yytext[0]; }

[ \t] { HANDLE_COLUMN; }
\n { sb->line_idx = 0; sb->line_no++; }

. { HANDLE_COLUMN; return PARSE_ERROR; }
%%

int yywrap(void)
{
	return 1;
}

void yyerror(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sql_parse_error(sb, yytext, fmt, ap);
	va_end(ap);
}
