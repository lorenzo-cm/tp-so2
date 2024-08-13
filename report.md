<!-- LTeX: language=pt-BR -->

# PAGINADOR DE MEMÓRIA -- RELATÓRIO

1. Termo de compromisso

    Ao entregar este documento preenchiso, os membros do grupo afirmam que todo o código desenvolvido para este trabalho é de autoria própria. Exceto pelo material listado no item 3 deste relatório, os membros do grupo afirmam não ter copiado material da Internet nem ter obtido código de terceiros.

2. Membros do grupo e alocação de esforço

    Preencha as linhas abaixo com o nome e o email dos integrantes do grupo.  Substitua marcadores `XX` pela contribuição de cada membro do grupo no desenvolvimento do trabalho (os valores devem somar 100%).

    * Lorenzo Carneiro Magalhaes <lorenzocarneirobr@gmail.com> 50%
    * Tomas Lacerda Muniz <tomastlm2000@gmail.com> 50%

3. Referências bibliográficas

Implementação das estruturas de dados do professor. Disponível em https://gitlab.dcc.ufmg.br/cunha-dcc605/mempager-assignment/-/blob/master/src/pager.c
Foi utilizado o chatGPT para sanar dúvidas relacionadas e debug.

4. Detalhes de implementação

    1. Descreva e justifique as estruturas de dados utilizadas em sua solução.
    2. Descreva o mecanismo utilizado para controle de acesso e modificação às páginas.

Como usamos a estrutura de dados que vi no gitlab do professor, a decisão das estruturas de dados já estava pronta. Então focamos em entender o funcionamento da estrutura. Primeiramente buscamos definir como -1 todos os campos não definidos ou não setados da estrutura. Um ponto especial foi a alocação dos processos, que na primeira abordagem cada processo foi definido como NULL no vetor pid2proc, indicando que não havia um processo associado, mas logo vimos que não era uma boa ideia, pois dificultava toda a implementação, além de que provavelmente não iria trazer muitas melhorias significativas.

Após resetar/limpar todos os processos no pager_init, fizemos pager_create, que basicamente seta o processo para o PID passado como parâmetro sem alocar nenhuma memória extra.

Depois fizemos o pager_destroy, que basicamente que fazia o mesmo processo de resetar/limpar as estruturas usadas pelo processo.

São essas as estruturas modificadas:
- Estrutura de processo (struct proc dentro de pager na variável pid2proc)
- As páginas relacionadas ao processo em questão (struct frame_data dentro de pager na variável frames)
- Blocos alocados ao processo em questão (vetor com valores de PID, indicando a qual processo eles respondem)
- Atualização das variáveis blocks_free e frames_free, indicando um aumento no número de cada recurso

O pager_extend, responsável por alocar memória ao processo, faz o processo inverso ao destroy, ele procura por blocos disponíveis (imaginamos que não seria necessário procurar blocos livres para alocar memória em um frame, mas seguimos as ordens), e aloca o bloco para o processo em questão mudando na variável pager.block2pid. Ele não aloca frames, conforme solicitado na documentação.

O pager_fault lida com falhas de páginas e principalmente na transferência de dados no disco para a memória. Essa transferência é feita quando tenta-se acessar um endereço que não está alocado. Aqui, conforme a documentação, eu assumi que os endereços alocados estão corretamente passados e não realize um tratamento de páginas que não são do processo em questão. Não realizei também pois não consegui pensar em um método para fazê-lo com base na estrutura utilizada.

Conforme descrito, ele aloca um frame se estiver disponível e utiliza o algoritmo da segunda chance caso não tenha um imediatamente disponível. O algoritmo da segunda chance ocorre exatamente como descrito na documentação.

E em seguida bastou resetar a pagina caso fosse nova e loadar do disco caso ela ja estivesse no disco e não na memória. Assim, a página é alocada na memória.

Também foi feito o tratamento para quando o page fault indica que o processo quer escrever, de maneira a garantir o direito de escrita.

Por fim, o pager syslog usou das mesmas técnicas de procurar o processo. Estávamos com um pouco de dificuldade, então sondamos soluções dos colegas, que nos explicaram como fazer.

Em suma, utilizamos as mesmas estruturas do professor:

- `struct frame_data`: Armazena informações sobre cada frame de memória física, incluindo o `pid` do processo que possui o frame, o índice da `page` correspondente, as permissões (`prot`) de acesso, e um flag `dirty` indicando se o frame foi modificado.

- `struct page_data`: Representa informações sobre cada página de memória de um processo, incluindo o índice do `block` no disco onde a página pode estar armazenada, se a página está `on_disk`, e o `frame` correspondente na memória física, se estiver presente.

- `struct proc`: Mantém informações sobre um processo específico, incluindo seu `pid`, o número de páginas alocadas (`npages`), o número máximo de páginas (`maxpages`), e um ponteiro para um array de `pages` que armazena dados sobre as páginas do processo.

- `struct pager`: Estrutura principal do sistema de paginação, que controla o acesso a recursos de memória. Inclui um mutex (`mutex`) para sincronização, o número total de frames (`nframes`) e blocos (`nblocks`), a contagem de frames e blocos livres, o ponteiro `frames` para o array de `frame_data`, o ponteiro `block2pid` que mapeia blocos para processos, e o ponteiro `pid2proc` que mapeia processos para suas estruturas `proc`.