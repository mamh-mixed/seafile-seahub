(this["webpackJsonpseahub-frontend"]=this["webpackJsonpseahub-frontend"]||[]).push([[41],{1855:function(e,t,r){"use strict";function n(e){var t,r,n=e.statementIndent,a=e.jsonld,i=e.json||a,o=e.typescript,u=e.wordCharacters||/[\w$\xa1-\uffff]/,s=function(){function e(e){return{type:e,style:"keyword"}}var t=e("keyword a"),r=e("keyword b"),n=e("keyword c"),a=e("keyword d"),i=e("operator"),o={type:"atom",style:"atom"};return{if:e("if"),while:t,with:t,else:r,do:r,try:r,finally:r,return:a,break:a,continue:a,new:e("new"),delete:n,void:n,throw:n,debugger:e("debugger"),var:e("var"),const:e("var"),let:e("var"),function:e("function"),catch:e("catch"),for:e("for"),switch:e("switch"),case:e("case"),default:e("default"),in:i,typeof:i,instanceof:i,true:o,false:o,null:o,undefined:o,NaN:o,Infinity:o,this:e("this"),class:e("class"),super:e("atom"),yield:n,export:e("export"),import:e("import"),extends:n,await:n}}(),c=/[+\-*&%=<>!?|~^@]/,f=/^@(context|id|value|language|type|container|list|set|reverse|index|base|vocab|graph)"/;function l(e,n,a){return t=e,r=a,n}function d(e,t){var r,n=e.next();if('"'==n||"'"==n)return t.tokenize=(r=n,function(e,t){var n,i=!1;if(a&&"@"==e.peek()&&e.match(f))return t.tokenize=d,l("jsonld-keyword","meta");for(;null!=(n=e.next())&&(n!=r||i);)i=!i&&"\\"==n;return i||(t.tokenize=d),l("string","string")}),t.tokenize(e,t);if("."==n&&e.match(/^\d[\d_]*(?:[eE][+\-]?[\d_]+)?/))return l("number","number");if("."==n&&e.match(".."))return l("spread","meta");if(/[\[\]{}\(\),;\:\.]/.test(n))return l(n);if("="==n&&e.eat(">"))return l("=>","operator");if("0"==n&&e.match(/^(?:x[\dA-Fa-f_]+|o[0-7_]+|b[01_]+)n?/))return l("number","number");if(/\d/.test(n))return e.match(/^[\d_]*(?:n|(?:\.[\d_]*)?(?:[eE][+\-]?[\d_]+)?)?/),l("number","number");if("/"==n)return e.eat("*")?(t.tokenize=m,m(e,t)):e.eat("/")?(e.skipToEnd(),l("comment","comment")):function(e,t,r){return t.tokenize==d&&/^(?:operator|sof|keyword [bcd]|case|new|export|default|spread|[\[{}\(,;:]|=>)$/.test(t.lastType)||"quasi"==t.lastType&&/\{\s*$/.test(e.string.slice(0,e.pos-(r||0)))}(e,t,1)?(function(e){for(var t,r=!1,n=!1;null!=(t=e.next());){if(!r){if("/"==t&&!n)return;"["==t?n=!0:n&&"]"==t&&(n=!1)}r=!r&&"\\"==t}}(e),e.match(/^\b(([gimyus])(?![gimyus]*\2))+\b/),l("regexp","string.special")):(e.eat("="),l("operator","operator",e.current()));if("`"==n)return t.tokenize=p,p(e,t);if("#"==n&&"!"==e.peek())return e.skipToEnd(),l("meta","meta");if("#"==n&&e.eatWhile(u))return l("variable","property");if("<"==n&&e.match("!--")||"-"==n&&e.match("->")&&!/\S/.test(e.string.slice(0,e.start)))return e.skipToEnd(),l("comment","comment");if(c.test(n))return">"==n&&t.lexical&&">"==t.lexical.type||(e.eat("=")?"!"!=n&&"="!=n||e.eat("="):/[<>*+\-|&?]/.test(n)&&(e.eat(n),">"==n&&e.eat(n))),"?"==n&&e.eat(".")?l("."):l("operator","operator",e.current());if(u.test(n)){e.eatWhile(u);var i=e.current();if("."!=t.lastType){if(s.propertyIsEnumerable(i)){var o=s[i];return l(o.type,o.style,i)}if("async"==i&&e.match(/^(\s|\/\*([^*]|\*(?!\/))*?\*\/)*[\[\(\w]/,!1))return l("async","keyword",i)}return l("variable","variable",i)}}function m(e,t){for(var r,n=!1;r=e.next();){if("/"==r&&n){t.tokenize=d;break}n="*"==r}return l("comment","comment")}function p(e,t){for(var r,n=!1;null!=(r=e.next());){if(!n&&("`"==r||"$"==r&&e.eat("{"))){t.tokenize=d;break}n=!n&&"\\"==r}return l("quasi","string.special",e.current())}function k(e,t){t.fatArrowAt&&(t.fatArrowAt=null);var r=e.string.indexOf("=>",e.start);if(!(r<0)){if(o){var n=/:\s*(?:\w+(?:<[^>]*>|\[\])?|\{[^}]*\})\s*$/.exec(e.string.slice(e.start,r));n&&(r=n.index)}for(var a=0,i=!1,s=r-1;s>=0;--s){var c=e.string.charAt(s),f="([{}])".indexOf(c);if(f>=0&&f<3){if(!a){++s;break}if(0==--a){"("==c&&(i=!0);break}}else if(f>=3&&f<6)++a;else if(u.test(c))i=!0;else if(/["'\/`]/.test(c))for(;;--s){if(0==s)return;if(e.string.charAt(s-1)==c&&"\\"!=e.string.charAt(s-2)){s--;break}}else if(i&&!a){++s;break}}i&&!a&&(t.fatArrowAt=s)}}var v={atom:!0,number:!0,variable:!0,string:!0,regexp:!0,this:!0,import:!0,"jsonld-keyword":!0};function y(e,t,r,n,a,i){this.indented=e,this.column=t,this.type=r,this.prev=a,this.info=i,null!=n&&(this.align=n)}function w(e,t){for(var r=e.localVars;r;r=r.next)if(r.name==t)return!0;for(var n=e.context;n;n=n.prev)for(r=n.vars;r;r=r.next)if(r.name==t)return!0}var b={state:null,column:null,marked:null,cc:null};function h(){for(var e=arguments.length-1;e>=0;e--)b.cc.push(arguments[e])}function x(){return h.apply(null,arguments),!0}function g(e,t){for(var r=t;r;r=r.next)if(r.name==e)return!0;return!1}function V(t){var r=b.state;if(b.marked="def",r.context)if("var"==r.lexical.info&&r.context&&r.context.block){var n=A(t,r.context);if(null!=n)return void(r.context=n)}else if(!g(t,r.localVars))return void(r.localVars=new T(t,r.localVars));e.globalVars&&!g(t,r.globalVars)&&(r.globalVars=new T(t,r.globalVars))}function A(e,t){if(t){if(t.block){var r=A(e,t.prev);return r?r==t.prev?t:new j(r,t.vars,!0):null}return g(e,t.vars)?t:new j(t.prev,new T(e,t.vars),!1)}return null}function z(e){return"public"==e||"private"==e||"protected"==e||"abstract"==e||"readonly"==e}function j(e,t,r){this.prev=e,this.vars=t,this.block=r}function T(e,t){this.name=e,this.next=t}var $=new T("this",new T("arguments",null));function O(){b.state.context=new j(b.state.context,b.state.localVars,!1),b.state.localVars=$}function _(){b.state.context=new j(b.state.context,b.state.localVars,!0),b.state.localVars=null}function q(){b.state.localVars=b.state.context.vars,b.state.context=b.state.context.prev}function E(e,t){var r=function(){var r=b.state,n=r.indented;if("stat"==r.lexical.type)n=r.lexical.indented;else for(var a=r.lexical;a&&")"==a.type&&a.align;a=a.prev)n=a.indented;r.lexical=new y(n,b.stream.column(),e,null,r.lexical,t)};return r.lex=!0,r}function I(){var e=b.state;e.lexical.prev&&(")"==e.lexical.type&&(e.indented=e.lexical.indented),e.lexical=e.lexical.prev)}function S(e){return function t(r){return r==e?x():";"==e||"}"==r||")"==r||"]"==r?h():x(t)}}function N(e,t){return"var"==e?x(E("vardef",t),be,S(";"),I):"keyword a"==e?x(E("form"),W,N,I):"keyword b"==e?x(E("form"),N,I):"keyword d"==e?b.stream.match(/^\s*$/,!1)?x():x(E("stat"),D,S(";"),I):"debugger"==e?x(S(";")):"{"==e?x(E("}"),_,ne,I,q):";"==e?x():"if"==e?("else"==b.state.lexical.info&&b.state.cc[b.state.cc.length-1]==I&&b.state.cc.pop()(),x(E("form"),W,N,I,ze)):"function"==e?x(Oe):"for"==e?x(E("form"),_,je,N,q,I):"class"==e||o&&"interface"==t?(b.marked="keyword",x(E("form","class"==e?e:t),Se,I)):"variable"==e?o&&"declare"==t?(b.marked="keyword",x(N)):o&&("module"==t||"enum"==t||"type"==t)&&b.stream.match(/^\s*\w/,!1)?(b.marked="keyword","enum"==t?x(Ke):"type"==t?x(qe,S("operator"),se,S(";")):x(E("form"),he,S("{"),E("}"),ne,I,I)):o&&"namespace"==t?(b.marked="keyword",x(E("form"),C,N,I)):o&&"abstract"==t?(b.marked="keyword",x(N)):x(E("stat"),R):"switch"==e?x(E("form"),W,S("{"),E("}","switch"),_,ne,I,I,q):"case"==e?x(C,S(":")):"default"==e?x(S(":")):"catch"==e?x(E("form"),O,P,N,I,q):"export"==e?x(E("stat"),Je,I):"import"==e?x(E("stat"),Be,I):"async"==e?x(N):"@"==t?x(C,N):h(E("stat"),C,S(";"),I)}function P(e){if("("==e)return x(Ee,S(")"))}function C(e,t){return B(e,t,!1)}function J(e,t){return B(e,t,!0)}function W(e){return"("!=e?h():x(E(")"),D,S(")"),I)}function B(e,t,r){if(b.state.fatArrowAt==b.stream.start){var n=r?L:K;if("("==e)return x(O,E(")"),te(Ee,")"),I,S("=>"),n,q);if("variable"==e)return h(O,he,S("=>"),n,q)}var a=r?U:F;return v.hasOwnProperty(e)?x(a):"function"==e?x(Oe,a):"class"==e||o&&"interface"==t?(b.marked="keyword",x(E("form"),Ie,I)):"keyword c"==e||"async"==e?x(r?J:C):"("==e?x(E(")"),D,S(")"),I,a):"operator"==e||"spread"==e?x(r?J:C):"["==e?x(E("]"),He,I,a):"{"==e?re(Y,"}",null,a):"quasi"==e?h(G,a):"new"==e?x(function(e){return function(t){return"."==t?x(e?Q:M):"variable"==t&&o?x(ve,e?U:F):h(e?J:C)}}(r)):x()}function D(e){return e.match(/[;\}\)\],]/)?h():h(C)}function F(e,t){return","==e?x(D):U(e,t,!1)}function U(e,t,r){var n=0==r?F:U,a=0==r?C:J;return"=>"==e?x(O,r?L:K,q):"operator"==e?/\+\+|--/.test(t)||o&&"!"==t?x(n):o&&"<"==t&&b.stream.match(/^([^<>]|<[^<>]*>)*>\s*\(/,!1)?x(E(">"),te(se,">"),I,n):"?"==t?x(C,S(":"),a):x(a):"quasi"==e?h(G,n):";"!=e?"("==e?re(J,")","call",n):"."==e?x(X,n):"["==e?x(E("]"),D,S("]"),I,n):o&&"as"==t?(b.marked="keyword",x(se,n)):"regexp"==e?(b.state.lastType=b.marked="operator",b.stream.backUp(b.stream.pos-b.stream.start-1),x(a)):void 0:void 0}function G(e,t){return"quasi"!=e?h():"${"!=t.slice(t.length-2)?x(G):x(D,H)}function H(e){if("}"==e)return b.marked="string.special",b.state.tokenize=p,x(G)}function K(e){return k(b.stream,b.state),h("{"==e?N:C)}function L(e){return k(b.stream,b.state),h("{"==e?N:J)}function M(e,t){if("target"==t)return b.marked="keyword",x(F)}function Q(e,t){if("target"==t)return b.marked="keyword",x(U)}function R(e){return":"==e?x(I,N):h(F,S(";"),I)}function X(e){if("variable"==e)return b.marked="property",x()}function Y(e,t){return"async"==e?(b.marked="property",x(Y)):"variable"==e||"keyword"==b.style?(b.marked="property","get"==t||"set"==t?x(Z):(o&&b.state.fatArrowAt==b.stream.start&&(r=b.stream.match(/^\s*:\s*/,!1))&&(b.state.fatArrowAt=b.stream.pos+r[0].length),x(ee))):"number"==e||"string"==e?(b.marked=a?"property":b.style+" property",x(ee)):"jsonld-keyword"==e?x(ee):o&&z(t)?(b.marked="keyword",x(Y)):"["==e?x(C,ae,S("]"),ee):"spread"==e?x(J,ee):"*"==t?(b.marked="keyword",x(Y)):":"==e?h(ee):void 0;var r}function Z(e){return"variable"!=e?h(ee):(b.marked="property",x(Oe))}function ee(e){return":"==e?x(J):"("==e?h(Oe):void 0}function te(e,t,r){function n(a,i){if(r?r.indexOf(a)>-1:","==a){var o=b.state.lexical;return"call"==o.info&&(o.pos=(o.pos||0)+1),x((function(r,n){return r==t||n==t?h():h(e)}),n)}return a==t||i==t?x():r&&r.indexOf(";")>-1?h(e):x(S(t))}return function(r,a){return r==t||a==t?x():h(e,n)}}function re(e,t,r){for(var n=3;n<arguments.length;n++)b.cc.push(arguments[n]);return x(E(t,r),te(e,t),I)}function ne(e){return"}"==e?x():h(N,ne)}function ae(e,t){if(o){if(":"==e)return x(se);if("?"==t)return x(ae)}}function ie(e,t){if(o&&(":"==e||"in"==t))return x(se)}function oe(e){if(o&&":"==e)return b.stream.match(/^\s*\w+\s+is\b/,!1)?x(C,ue,se):x(se)}function ue(e,t){if("is"==t)return b.marked="keyword",x()}function se(e,t){return"keyof"==t||"typeof"==t||"infer"==t||"readonly"==t?(b.marked="keyword",x("typeof"==t?J:se)):"variable"==e||"void"==t?(b.marked="type",x(ke)):"|"==t||"&"==t?x(se):"string"==e||"number"==e||"atom"==e?x(ke):"["==e?x(E("]"),te(se,"]",","),I,ke):"{"==e?x(E("}"),fe,I,ke):"("==e?x(te(pe,")"),ce,ke):"<"==e?x(te(se,">"),se):"quasi"==e?h(de,ke):void 0}function ce(e){if("=>"==e)return x(se)}function fe(e){return e.match(/[\}\)\]]/)?x():","==e||";"==e?x(fe):h(le,fe)}function le(e,t){return"variable"==e||"keyword"==b.style?(b.marked="property",x(le)):"?"==t||"number"==e||"string"==e?x(le):":"==e?x(se):"["==e?x(S("variable"),ie,S("]"),le):"("==e?h(_e,le):e.match(/[;\}\)\],]/)?void 0:x()}function de(e,t){return"quasi"!=e?h():"${"!=t.slice(t.length-2)?x(de):x(se,me)}function me(e){if("}"==e)return b.marked="string-2",b.state.tokenize=p,x(de)}function pe(e,t){return"variable"==e&&b.stream.match(/^\s*[?:]/,!1)||"?"==t?x(pe):":"==e?x(se):"spread"==e?x(pe):h(se)}function ke(e,t){return"<"==t?x(E(">"),te(se,">"),I,ke):"|"==t||"."==e||"&"==t?x(se):"["==e?x(se,S("]"),ke):"extends"==t||"implements"==t?(b.marked="keyword",x(se)):"?"==t?x(se,S(":"),se):void 0}function ve(e,t){if("<"==t)return x(E(">"),te(se,">"),I,ke)}function ye(){return h(se,we)}function we(e,t){if("="==t)return x(se)}function be(e,t){return"enum"==t?(b.marked="keyword",x(Ke)):h(he,ae,Ve,Ae)}function he(e,t){return o&&z(t)?(b.marked="keyword",x(he)):"variable"==e?(V(t),x()):"spread"==e?x(he):"["==e?re(ge,"]"):"{"==e?re(xe,"}"):void 0}function xe(e,t){return"variable"!=e||b.stream.match(/^\s*:/,!1)?("variable"==e&&(b.marked="property"),"spread"==e?x(he):"}"==e?h():"["==e?x(C,S("]"),S(":"),xe):x(S(":"),he,Ve)):(V(t),x(Ve))}function ge(){return h(he,Ve)}function Ve(e,t){if("="==t)return x(J)}function Ae(e){if(","==e)return x(be)}function ze(e,t){if("keyword b"==e&&"else"==t)return x(E("form","else"),N,I)}function je(e,t){return"await"==t?x(je):"("==e?x(E(")"),Te,I):void 0}function Te(e){return"var"==e?x(be,$e):"variable"==e?x($e):h($e)}function $e(e,t){return")"==e?x():";"==e?x($e):"in"==t||"of"==t?(b.marked="keyword",x(C,$e)):h(C,$e)}function Oe(e,t){return"*"==t?(b.marked="keyword",x(Oe)):"variable"==e?(V(t),x(Oe)):"("==e?x(O,E(")"),te(Ee,")"),I,oe,N,q):o&&"<"==t?x(E(">"),te(ye,">"),I,Oe):void 0}function _e(e,t){return"*"==t?(b.marked="keyword",x(_e)):"variable"==e?(V(t),x(_e)):"("==e?x(O,E(")"),te(Ee,")"),I,oe,q):o&&"<"==t?x(E(">"),te(ye,">"),I,_e):void 0}function qe(e,t){return"keyword"==e||"variable"==e?(b.marked="type",x(qe)):"<"==t?x(E(">"),te(ye,">"),I):void 0}function Ee(e,t){return"@"==t&&x(C,Ee),"spread"==e?x(Ee):o&&z(t)?(b.marked="keyword",x(Ee)):o&&"this"==e?x(ae,Ve):h(he,ae,Ve)}function Ie(e,t){return"variable"==e?Se(e,t):Ne(e,t)}function Se(e,t){if("variable"==e)return V(t),x(Ne)}function Ne(e,t){return"<"==t?x(E(">"),te(ye,">"),I,Ne):"extends"==t||"implements"==t||o&&","==e?("implements"==t&&(b.marked="keyword"),x(o?se:C,Ne)):"{"==e?x(E("}"),Pe,I):void 0}function Pe(e,t){return"async"==e||"variable"==e&&("static"==t||"get"==t||"set"==t||o&&z(t))&&b.stream.match(/^\s+#?[\w$\xa1-\uffff]/,!1)?(b.marked="keyword",x(Pe)):"variable"==e||"keyword"==b.style?(b.marked="property",x(Ce,Pe)):"number"==e||"string"==e?x(Ce,Pe):"["==e?x(C,ae,S("]"),Ce,Pe):"*"==t?(b.marked="keyword",x(Pe)):o&&"("==e?h(_e,Pe):";"==e||","==e?x(Pe):"}"==e?x():"@"==t?x(C,Pe):void 0}function Ce(e,t){if("!"==t||"?"==t)return x(Ce);if(":"==e)return x(se,Ve);if("="==t)return x(J);var r=b.state.lexical.prev;return h(r&&"interface"==r.info?_e:Oe)}function Je(e,t){return"*"==t?(b.marked="keyword",x(Ge,S(";"))):"default"==t?(b.marked="keyword",x(C,S(";"))):"{"==e?x(te(We,"}"),Ge,S(";")):h(N)}function We(e,t){return"as"==t?(b.marked="keyword",x(S("variable"))):"variable"==e?h(J,We):void 0}function Be(e){return"string"==e?x():"("==e?h(C):"."==e?h(F):h(De,Fe,Ge)}function De(e,t){return"{"==e?re(De,"}"):("variable"==e&&V(t),"*"==t&&(b.marked="keyword"),x(Ue))}function Fe(e){if(","==e)return x(De,Fe)}function Ue(e,t){if("as"==t)return b.marked="keyword",x(De)}function Ge(e,t){if("from"==t)return b.marked="keyword",x(C)}function He(e){return"]"==e?x():h(te(J,"]"))}function Ke(){return h(E("form"),he,S("{"),E("}"),te(Le,"}"),I,I)}function Le(){return h(he,Ve)}return O.lex=_.lex=!0,q.lex=!0,I.lex=!0,{name:e.name,startState:function(t){var r={tokenize:d,lastType:"sof",cc:[],lexical:new y(-t,0,"block",!1),localVars:e.localVars,context:e.localVars&&new j(null,null,!1),indented:0};return e.globalVars&&"object"==typeof e.globalVars&&(r.globalVars=e.globalVars),r},token:function(e,n){if(e.sol()&&(n.lexical.hasOwnProperty("align")||(n.lexical.align=!1),n.indented=e.indentation(),k(e,n)),n.tokenize!=m&&e.eatSpace())return null;var a=n.tokenize(e,n);return"comment"==t?a:(n.lastType="operator"!=t||"++"!=r&&"--"!=r?t:"incdec",function(e,t,r,n,a){var o=e.cc;for(b.state=e,b.stream=a,b.marked=null,b.cc=o,b.style=t,e.lexical.hasOwnProperty("align")||(e.lexical.align=!0);;)if((o.length?o.pop():i?C:N)(r,n)){for(;o.length&&o[o.length-1].lex;)o.pop()();return b.marked?b.marked:"variable"==r&&w(e,n)?"variableName.local":t}}(n,a,t,r,e))},indent:function(t,r,a){if(t.tokenize==m||t.tokenize==p)return null;if(t.tokenize!=d)return 0;var i,o=r&&r.charAt(0),u=t.lexical;if(!/^\s*else\b/.test(r))for(var s=t.cc.length-1;s>=0;--s){var f=t.cc[s];if(f==I)u=u.prev;else if(f!=ze&&f!=q)break}for(;("stat"==u.type||"form"==u.type)&&("}"==o||(i=t.cc[t.cc.length-1])&&(i==F||i==U)&&!/^[,\.=+\-*:?[\(]/.test(r));)u=u.prev;n&&")"==u.type&&"stat"==u.prev.type&&(u=u.prev);var l=u.type,k=o==l;return"vardef"==l?u.indented+("operator"==t.lastType||","==t.lastType?u.info.length+1:0):"form"==l&&"{"==o?u.indented:"form"==l?u.indented+a.unit:"stat"==l?u.indented+(function(e,t){return"operator"==e.lastType||","==e.lastType||c.test(t.charAt(0))||/[,.]/.test(t.charAt(0))}(t,r)?n||a.unit:0):"switch"!=u.info||k||0==e.doubleIndentSwitch?u.align?u.column+(k?0:1):u.indented+(k?0:a.unit):u.indented+(/^(?:case|default)\b/.test(r)?a.unit:2*a.unit)},languageData:{indentOnInput:/^\s*(?:case .*?:|default:|\{|\})$/,commentTokens:i?void 0:{line:"//",block:{open:"/*",close:"*/"}},closeBrackets:{brackets:["(","[","{","'",'"',"`"]},wordChars:"$"}}}r.r(t),r.d(t,"javascript",(function(){return a})),r.d(t,"json",(function(){return i})),r.d(t,"jsonld",(function(){return o})),r.d(t,"typescript",(function(){return u}));var a=n({name:"javascript"}),i=n({name:"json",json:!0}),o=n({name:"json",jsonld:!0}),u=n({name:"typescript",typescript:!0})}}]);
//# sourceMappingURL=41.chunk.js.map