### **Manipulação de Arrays e Collections**
- `collect()` - Criar collection
- `data_fill()` - Preencher dados faltantes
- `data_forget()` - Remover item por notação de ponto
- `data_get()` - Obter item por notação de ponto
- `data_set()` - Definir item por notação de ponto
- `head()` - Primeiro elemento do array
- `last()` - Último elemento do array# Helpers Laravel - Guia Completo

| Helper | Descrição | Exemplo de Uso |
|--------|-----------|----------------|
| `abort()` | Lança uma HttpException com os dados fornecidos | `abort(404, 'Página não encontrada')` |
| `abort_if()` | Lança uma HttpException se a condição for verdadeira | `abort_if(!$user, 403, 'Acesso negado')` |
| `abort_unless()` | Lança uma HttpException a menos que a condição seja verdadeira | `abort_unless($user->isAdmin(), 403)` |
| `action()` | Gera a URL para uma ação do controller | `action('UserController@show', ['id' => 1])` |
| `app()` | Obtém a instância do container disponível | `app('config')` ou `app()` |
| `app_path()` | Obtém o caminho para a pasta da aplicação | `app_path('Models/User.php')` |
| `append_config()` | Atribui IDs numéricos altos a itens de configuração para forçar anexação | `append_config(['item1', 'item2'])` |
| `asset()` | Gera um caminho de asset para a aplicação | `asset('css/app.css')` |
| `auth()` | Obtém a instância de autenticação disponível | `auth()->user()` ou `auth('admin')` |
| `back()` | Cria uma nova resposta de redirecionamento para a localização anterior | `back()->with('message', 'Sucesso!')` |
| `base_path()` | Obtém o caminho para a base da instalação | `base_path('composer.json')` |
| `bcrypt()` | Faz hash do valor fornecido usando o algoritmo bcrypt | `bcrypt('minha-senha')` |
| `blank()` | Determina se um valor está "vazio" (null, string vazia, array vazio, etc.) | `blank('')` → `true`, `blank('texto')` → `false` |
| `broadcast()` | Inicia a transmissão de um evento | `broadcast(new OrderShipped($order))` |
| `cache()` | Obtém/define o valor do cache especificado | `cache('key', 'default')` ou `cache(['key' => 'value'])` |
| `class_basename()` | Obtém o nome base da classe de um objeto ou string de classe | `class_basename('App\Models\User')` → `'User'` |
| `class_uses_recursive()` | Retorna todos os traits usados por uma classe, suas classes pai e traits dos traits | `class_uses_recursive(MinhaClasse::class)` |
| `collect()` | Cria uma collection a partir do valor fornecido | `collect([1, 2, 3])->map(fn($i) => $i * 2)` |
| `config()` | Obtém/define o valor de configuração especificado | `config('app.name')` ou `config(['app.name' => 'MyApp'])` |
| `config_path()` | Obtém o caminho de configuração | `config_path('services.php')` |
| `context()` | Obtém/define o valor de contexto especificado para logs | `context('user_id', 123)` |
| `cookie()` | Cria uma nova instância de cookie | `cookie('name', 'value', 60)` |
| `csrf_field()` | Gera um campo de formulário com token CSRF | `csrf_field()` → input hidden com token |
| `csrf_token()` | Obtém o valor do token CSRF | `csrf_token()` |
| `data_fill()` | Preenche dados onde estão faltando usando notação de ponto | `data_fill($array, 'user.name', 'João')` |
| `data_forget()` | Remove/desdefine um item de array ou objeto usando notação de ponto | `data_forget($array, 'user.email')` |
| `data_get()` | Obtém um item de array ou objeto usando notação de ponto | `data_get($array, 'user.profile.name')` |
| `data_set()` | Define um item em array ou objeto usando notação de ponto | `data_set($array, 'user.name', 'João')` |
| `database_path()` | Obtém o caminho do banco de dados | `database_path('migrations')` |
| `decrypt()` | Descriptografa o valor fornecido | `decrypt($encrypted_value)` |
| `defer()` | Adia a execução do callback fornecido | `defer(fn() => cleanup_operation())` |
| `dispatch()` | Despacha um job para seu manipulador apropriado | `dispatch(new ProcessOrder($order))` |
| `dispatch_sync()` | Despacha um comando para seu manipulador no processo atual | `dispatch_sync(new ProcessOrder($order))` |
| `e()` | Codifica caracteres especiais HTML em uma string para prevenir XSS | `e('<script>alert("xss")</script>')` → string segura |
| `encrypt()` | Criptografa o valor fornecido | `encrypt('dados-sensíveis')` |
| `env()` | Obtém o valor de uma variável de ambiente | `env('APP_NAME', 'Laravel')` |
| `event()` | Despacha um evento e chama os listeners | `event(new UserRegistered($user))` |
| `fake()` | Obtém uma instância do faker para testes | `fake()->name()` |
| `filled()` | Determina se um valor está "preenchido" (oposto de blank) | `filled('texto')` → `true`, `filled('')` → `false` |
| `fluent()` | Cria um objeto Fluent a partir de um array ou objeto | `fluent(['nome' => 'João'])->nome` |
| `head()` | Obtém o primeiro elemento de um array (útil para encadeamento de métodos) | `head([1, 2, 3])` → `1` |
| `info()` | Escreve informações no log | `info('Operação concluída', ['user_id' => 1])` |
| `lang_path()` | Obtém o caminho para a pasta de idiomas | `lang_path('pt')` |
| `laravel_cloud()` | Determina se a aplicação está rodando no Laravel Cloud | `laravel_cloud()` → `true` ou `false` |
| `last()` | Obtém o último elemento de um array | `last([1, 2, 3])` → `3` |
| `literal()` | Retorna um objeto literal/anônimo usando argumentos nomeados | `literal(nome: 'João', idade: 30)` |
| `logger()` | Registra uma mensagem de debug nos logs | `logger('Debug info')` ou `logger()` |
| `logs()` | Obtém uma instância do driver de log | `logs('slack')` |
| `method_field()` | Gera um campo de formulário para falsificar o verbo HTTP | `method_field('PUT')` |
| `mix()` | Obtém o caminho para um arquivo versionado do Mix | `mix('js/app.js')` |
| `now()` | Cria uma nova instância Carbon para o tempo atual | `now()` ou `now('America/Sao_Paulo')` |
| `object_get()` | Obtém um item de um objeto usando notação de ponto | `object_get($obj, 'usuario.nome')` |
| `old()` | Recupera um item de entrada antigo | `old('email')` |
| `once()` | Garante que um callable seja chamado apenas uma vez, retornando o resultado em chamadas subsequentes | `once(fn() => expensive_operation())` |
| `optional()` | Fornece acesso seguro a objetos opcionais, evitando erros de null | `optional($user)->name` |
| `policy()` | Obtém uma instância de policy para uma classe fornecida | `policy(Post::class)` |
| `precognitive()` | Manipula um hook de controller Precognition | `precognitive(fn($when) => $when(...))` |
| `preg_replace_array()` | Substitui um padrão com cada valor do array sequencialmente | `preg_replace_array('/\?/', ['a', 'b'], '? e ?')` → `'a e b'` |
| `public_path()` | Obtém o caminho para a pasta pública | `public_path('images/logo.png')` |
| `redirect()` | Obtém uma instância do redirecionador | `redirect('/home')` ou `redirect()` |
| `report()` | Reporta uma exceção | `report($exception)` |
| `report_if()` | Reporta uma exceção se a condição for verdadeira | `report_if($condition, $exception)` |
| `report_unless()` | Reporta uma exceção a menos que a condição seja verdadeira | `report_unless($condition, $exception)` |
| `request()` | Obtém uma instância da requisição atual ou um item de entrada | `request('email')` ou `request()` |
| `rescue()` | Captura uma exceção potencial e retorna um valor padrão | `rescue(fn() => risky_operation(), 'default')` |
| `resolve()` | Resolve um serviço do container | `resolve('App\Services\PaymentService')` |
| `resource_path()` | Obtém o caminho para a pasta de recursos | `resource_path('views/emails')` |
| `response()` | Retorna uma nova resposta da aplicação | `response()->json(['status' => 'ok'])` |
| `retry()` | Tenta executar uma operação um determinado número de vezes | `retry(3, fn() => api_call())` |
| `route()` | Gera a URL para uma rota nomeada | `route('user.profile', ['id' => 1])` |
| `secure_asset()` | Gera um caminho de asset com HTTPS | `secure_asset('css/app.css')` |
| `secure_url()` | Gera uma URL HTTPS para a aplicação | `secure_url('/admin')` |
| `session()` | Obtém/define o valor de sessão especificado | `session('user_id')` ou `session(['key' => 'value'])` |
| `storage_path()` | Obtém o caminho para a pasta de armazenamento | `storage_path('app/uploads')` |
| `str()` | Obtém um novo objeto stringable da string fornecida | `str('hello')->upper()` → `'HELLO'` |
| `tap()` | Chama o Closure fornecido com o valor e retorna o valor | `tap($user, fn($u) => $u->save())` |
| `throw_if()` | Lança uma exceção se a condição for verdadeira | `throw_if($errors, 'Erro encontrado')` |
| `throw_unless()` | Lança uma exceção a menos que a condição seja verdadeira | `throw_unless($user, 'Usuário não encontrado')` |
| `to_route()` | Cria uma nova resposta de redirecionamento para uma rota nomeada | `to_route('dashboard')` |
| `today()` | Cria uma nova instância Carbon para a data atual | `today()` ou `today('America/Sao_Paulo')` |
| `trait_uses_recursive()` | Retorna todos os traits usados por um trait e seus traits | `trait_uses_recursive(MeuTrait::class)` |
| `trans()` | Traduz a mensagem fornecida | `trans('messages.welcome')` |
| `trans_choice()` | Traduz a mensagem baseada em uma contagem | `trans_choice('messages.apples', $count)` |
| `transform()` | Transforma o valor fornecido se estiver presente | `transform($value, fn($v) => strtoupper($v))` |
| `url()` | Gera uma URL para a aplicação | `url('/profile')` ou `url()` |
| `validator()` | Cria uma nova instância Validator | `validator($data, $rules)` |
| `value()` | Retorna o valor padrão do valor fornecido (resolve Closures) | `value(fn() => 'test')` → `'test'` |
| `view()` | Obtém o conteúdo da view avaliada | `view('welcome', ['name' => 'João'])` |
| `when()` | Retorna um valor se a condição fornecida for verdadeira | `when($user, fn() => 'Logado', 'Visitante')` |
| `windows_os()` | Determina se o ambiente atual é baseado em Windows | `windows_os()` → `true` no Windows |
| `with()` | Retorna o valor fornecido, opcionalmente passado através do callback | `with($user, fn($u) => $u->name)` |
| `__()` | Traduz a mensagem fornecida (alias para trans) | `__('messages.welcome')` |

## Categorias de Helpers

### **HTTP e Respostas**
- `abort()` - Lança HttpException
- `abort_if()` - Lança HttpException condicional
- `abort_unless()` - Lança HttpException condicional inversa
- `back()` - Redirecionamento para página anterior
- `redirect()` - Redirecionamento
- `response()` - Criar resposta HTTP
- `to_route()` - Redirecionamento para rota nomeada

### **URLs e Rotas**
- `action()` - URL para ação do controller
- `asset()` - Caminho de asset
- `route()` - URL para rota nomeada
- `secure_asset()` - Asset com HTTPS
- `secure_url()` - URL com HTTPS
- `url()` - Gerar URL

### **Autenticação e Autorização**
- `auth()` - Instância de autenticação
- `policy()` - Instância de policy

### **Caminhos do Sistema**
- `app_path()` - Caminho da aplicação
- `base_path()` - Caminho base
- `config_path()` - Caminho de configuração
- `database_path()` - Caminho do banco
- `lang_path()` - Caminho de idiomas
- `public_path()` - Caminho público
- `resource_path()` - Caminho de recursos
- `storage_path()` - Caminho de armazenamento

### **Container e Dependências**
- `app()` - Container da aplicação
- `resolve()` - Resolver serviço do container

### **Validação de Valores**
- `blank()` - Verifica se está vazio
- `filled()` - Verifica se está preenchido

### **Manipulação de Classes**
- `class_basename()` - Nome base da classe
- `class_uses_recursive()` - Traits recursivos
- `trait_uses_recursive()` - Traits de um trait

### **Segurança e Criptografia**
- `bcrypt()` - Hash bcrypt
- `csrf_field()` - Campo CSRF
- `csrf_token()` - Token CSRF
- `decrypt()` - Descriptografar
- `e()` - Escape HTML
- `encrypt()` - Criptografar
- `method_field()` - Campo de método HTTP

### **Sessão e Cache**
- `cache()` - Gerenciar cache
- `old()` - Recuperar entrada antiga
- `session()` - Gerenciar sessão

### **Configuração e Ambiente**
- `append_config()` - Anexar configurações
- `config()` - Gerenciar configuração
- `env()` - Variáveis de ambiente
- `laravel_cloud()` - Detecção Laravel Cloud
- `windows_os()` - Detecção Windows

### **Data e Tempo**
- `now()` - Data/hora atual
- `today()` - Data atual

### **Tradução**
- `trans()` - Traduzir mensagem
- `trans_choice()` - Tradução por contagem
- `__()` - Alias para tradução

### **Jobs e Eventos**
- `broadcast()` - Transmitir evento
- `defer()` - Adiar execução
- `dispatch()` - Despachar job
- `dispatch_sync()` - Despachar job sincronamente
- `event()` - Despachar evento

### **Logs e Contexto**
- `context()` - Contexto de logs
- `info()` - Log de informação
- `logger()` - Logger
- `logs()` - Driver de log

### **Tratamento de Erros**
- `report()` - Reportar exceção
- `report_if()` - Reportar exceção condicional
- `report_unless()` - Reportar exceção condicional inversa
- `rescue()` - Capturar exceção
- `throw_if()` - Lança exceção condicional
- `throw_unless()` - Lança exceção condicional inversa

### **Manipulação de Dados**
- `cookie()` - Gerenciar cookies
- `fluent()` - Objeto fluente
- `literal()` - Objeto literal
- `object_get()` - Acesso por notação de ponto
- `optional()` - Acesso seguro a objetos

### **Controle de Fluxo**
- `once()` - Execução única
- `retry()` - Tentativas de execução
- `tap()` - Execução com retorno
- `transform()` - Transformação condicional
- `value()` - Resolver valor/Closure
- `when()` - Valor condicional
- `with()` - Aplicação de callback

### **Strings e Regex**
- `str()` - Objeto stringable
- `preg_replace_array()` - Substituição por array

### **Requisições e Views**
- `precognitive()` - Hook Precognition
- `request()` - Instância da requisição
- `validator()` - Criar validator
- `view()` - Renderizar view

### **Assets e Mix**
- `fake()` - Instância faker
- `mix()` - Arquivo versionado Mix