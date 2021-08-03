%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sqlhist-parse.h"

extern int yylex(void);
extern void yyerror(char *fmt, ...);

#define CHECK_RETURN_PTR(x)					\
	do {							\
		if (!(x)) {					\
			printf("FAILED MEMORY: %s\n", #x);	\
			return -ENOMEM;				\
		}						\
	} while (0)

#define CHECK_RETURN_VAL(x)					\
	do {							\
		if ((x) < 0) {					\
			printf("FAILED MEMORY: %s\n", #x);	\
			return -ENOMEM;				\
		}						\
	} while (0)

%}

%union {
	int	s32;
	char	*string;
	long	number;
	void	*expr;
}

%token AS SELECT FROM JOIN ON PARSE_ERROR
%token <number> NUMBER
%token <string> STRING
%token <string> FIELD
%token <string> LE GE EQ NEQ AND OR

%left '+' '-'
%left '*' '/'
%left '<' '>'
%left AND OR

%type <string> name label

%type <expr>  selection_expr field item named_field join_clause
%type <expr>  selection_addition

%%

start :
   select_statement
 ;

label : AS name { CHECK_RETURN_PTR($$ = store_str(sb, $2)); }
 | name { CHECK_RETURN_PTR($$ = store_str(sb, $1)); }
 ;

select : SELECT  { table_start(sb); }
  ;

select_statement :
    select selection_list table_exp
  ;

selection_list :
   selection
 | selection ',' selection_list
 ;

selection :
    selection_expr
				{
					CHECK_RETURN_VAL(add_selection(sb, $1, NULL));
				}
  | selection_expr label
				{
					CHECK_RETURN_VAL(add_selection(sb, $1, $2));
				}
  ;

selection_expr :
   field
 | '(' field ')'		{  $$ = $2; }
 | selection_addition
 | '(' selection_addition ')'	{  $$ = $2; }
 ;

selection_addition :
   field '+' field
				{
					$$ = add_compare(sb, $1, $3, COMPARE_ADD);
					CHECK_RETURN_PTR($$);
				}
 | field '-' field
				{
					$$ = add_compare(sb, $1, $3, COMPARE_SUB);
					CHECK_RETURN_PTR($$);
				}
 ;

item :
   named_field
 | field
 ;

field :
   FIELD	{ $$ = add_field(sb, $1, NULL); CHECK_RETURN_PTR($$); }
 ;

named_field :
   FIELD label { $$ = add_field(sb, $1, $2); CHECK_RETURN_PTR($$); }
 ;

name :
   FIELD
 ;

table_exp :
   from_clause join_clause
 ;

from_clause :
   FROM item		{ CHECK_RETURN_VAL(add_from(sb, $2)); }

/*
 * Select from a from clause confuses the variable parsing.
 * disable it for now.

   | FROM '(' select_statement ')' label
				{
					from_table_end($5);
					$$ = store_printf("FROM (%s) AS %s", $3, $5);
				}
*/
 ;

join_clause :
  JOIN item ON match_clause	{ add_to(sb, $2); }
 ;

match :
   item '=' item { CHECK_RETURN_VAL(add_match(sb, $1, $3)); }
 | item EQ item { CHECK_RETURN_VAL(add_match(sb, $1, $3)); }

 ;

match_clause :
   match
 | match ',' match_clause
 ;

%%
