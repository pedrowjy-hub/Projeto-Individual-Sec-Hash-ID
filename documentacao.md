### Cache em entradas repetidas

A opção `--cache` armazena o resultado de `identify()` por entrada.

Teste realizado com 1.000.000 de linhas contendo o mesmo hash:

| Modo | Tempo | Memória |
|---|---:|---:|
| Sem cache | 0.11s | 30820KB |
| Com cache | 0.09s | 30728KB |
