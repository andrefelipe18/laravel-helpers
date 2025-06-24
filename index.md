# Laravel Helpers - Guia Completo

## Índice de Helpers

| Helper                                            | Descrição                                                  |
| ------------------------------------------------- | ---------------------------------------------------------- |
| [`__()`](#__)                                     | Traduz mensagem (alias para `trans()`)                     |
| [`abort()`](#abort)                               | Lança `HttpException` com dados fornecidos                 |
| [`abort_if()`](#abort-if)                         | Lança `HttpException` se condição for verdadeira           |
| [`abort_unless()`](#abort-unless)                 | Lança `HttpException` a menos que condição seja verdadeira |
| [`action()`](#action)                             | Gera URL para ação do controller                           |
| [`app()`](#app)                                   | Obtém instância do container                               |
| [`app_path()`](#app-path)                         | Obtém caminho da pasta da aplicação                        |
| [`append_config()`](#append-config)               | Anexa itens de configuração                                |
| [`asset()`](#asset)                               | Gera caminho de asset                                      |
| [`auth()`](#auth)                                 | Obtém instância de autenticação                            |
| [`back()`](#back)                                 | Redirecionamento para página anterior                      |
| [`base_path()`](#base-path)                       | Obtém caminho base da instalação                           |
| [`bcrypt()`](#bcrypt)                             | Faz hash usando algoritmo `bcrypt`                         |
| [`blank()`](#blank)                               | Verifica se valor está vazio                               |
| [`broadcast()`](#broadcast)                       | Inicia transmissão de evento                               |
| [`cache()`](#cache)                               | Gerencia valores do cache                                  |
| [`class_basename()`](#class-basename)             | Obtém nome base da classe                                  |
| [`class_uses_recursive()`](#class-uses-recursive) | Retorna traits usados recursivamente                       |
| [`collect()`](#collect)                           | Cria collection a partir de valor                          |
| [`config()`](#config)                             | Gerencia valores de configuração                           |
| [`config_path()`](#config-path)                   | Obtém caminho de configuração                              |
| [`context()`](#context)                           | Gerencia contexto para logs                                |
| [`cookie()`](#cookie)                             | Cria instância de cookie                                   |
| [`csrf_field()`](#csrf-field)                     | Gera campo de formulário CSRF                              |
| [`csrf_token()`](#csrf-token)                     | Obtém token CSRF                                           |
| [`data_fill()`](#data-fill)                       | Preenche dados faltantes                                   |
| [`data_forget()`](#data-forget)                   | Remove item por notação de ponto                           |
| [`data_get()`](#data-get)                         | Obtém item por notação de ponto                            |
| [`data_set()`](#data-set)                         | Define item por notação de ponto                           |
| [`database_path()`](#database-path)               | Obtém caminho do banco de dados                            |
| [`decrypt()`](#decrypt)                           | Descriptografa valor                                       |
| [`defer()`](#defer)                               | Adia execução de callback                                  |
| [`dispatch()`](#dispatch)                         | Despacha job para manipulador                              |
| [`dispatch_sync()`](#dispatch-sync)               | Despacha comando no processo atual                         |
| [`e()`](#e)                                       | Codifica caracteres HTML para prevenir XSS                 |
| [`encrypt()`](#encrypt)                           | Criptografa valor                                          |
| [`env()`](#env)                                   | Obtém valor de variável de ambiente                        |
| [`event()`](#event)                               | Despacha evento e chama listeners                          |
| [`fake()`](#fake)                                 | Obtém instância do faker para testes                       |
| [`filled()`](#filled)                             | Verifica se valor está preenchido                          |
| [`fluent()`](#fluent)                             | Cria objeto Fluent                                         |
| [`head()`](#head)                                 | Obtém primeiro elemento do array                           |
| [`info()`](#info)                                 | Escreve informações no log                                 |
| [`lang_path()`](#lang-path)                       | Obtém caminho da pasta de idiomas                          |
| [`laravel_cloud()`](#laravel-cloud)               | Verifica se está rodando no Laravel Cloud                  |
| [`last()`](#last)                                 | Obtém último elemento do array                             |
| [`literal()`](#literal)                           | Retorna objeto literal usando argumentos nomeados          |
| [`logger()`](#logger)                             | Registra mensagem de debug nos logs                        |
| [`logs()`](#logs)                                 | Obtém instância do driver de log                           |
| [`method_field()`](#method-field)                 | Gera campo para falsificar verbo HTTP                      |
| [`mix()`](#mix)                                   | Obtém caminho para arquivo versionado do Mix               |
| [`now()`](#now)                                   | Cria instância Carbon para tempo atual                     |
| [`object_get()`](#object-get)                     | Obtém item de objeto por notação de ponto                  |
| [`old()`](#old)                                   | Recupera item de entrada antigo                            |
| [`once()`](#once)                                 | Garante execução única de callable                         |
| [`optional()`](#optional)                         | Fornece acesso seguro a objetos opcionais                  |
| [`policy()`](#policy)                             | Obtém instância de policy                                  |
| [`precognitive()`](#precognitive)                 | Manipula hook de controller Precognition                   |
| [`preg_replace_array()`](#preg-replace-array)     | Substitui padrão com valores do array                      |
| [`public_path()`](#public-path)                   | Obtém caminho da pasta pública                             |
| [`redirect()`](#redirect)                         | Obtém instância do redirecionador                          |
| [`report()`](#report)                             | Reporta exceção                                            |
| [`report_if()`](#report-if)                       | Reporta exceção se condição for verdadeira                 |
| [`report_unless()`](#report-unless)               | Reporta exceção a menos que condição seja verdadeira       |
| [`request()`](#request)                           | Obtém instância da requisição atual                        |
| [`rescue()`](#rescue)                             | Captura exceção e retorna valor padrão                     |
| [`resolve()`](#resolve)                           | Resolve serviço do container                               |
| [`resource_path()`](#resource-path)               | Obtém caminho da pasta de recursos                         |
| [`response()`](#response)                         | Retorna nova resposta da aplicação                         |
| [`retry()`](#retry)                               | Tenta executar operação múltiplas vezes                    |
| [`route()`](#route)                               | Gera URL para rota nomeada                                 |
| [`secure_asset()`](#secure-asset)                 | Gera caminho de asset com HTTPS                            |
| [`secure_url()`](#secure-url)                     | Gera URL HTTPS                                             |
| [`session()`](#session)                           | Gerencia valores de sessão                                 |
| [`storage_path()`](#storage-path)                 | Obtém caminho da pasta de armazenamento                    |
| [`str()`](#str)                                   | Obtém objeto stringable                                    |
| [`tap()`](#tap)                                   | Chama Closure com valor e retorna valor                    |
| [`throw_if()`](#throw-if)                         | Lança exceção se condição for verdadeira                   |
| [`throw_unless()`](#throw-unless)                 | Lança exceção a menos que condição seja verdadeira         |
| [`to_route()`](#to-route)                         | Cria redirecionamento para rota nomeada                    |
| [`today()`](#today)                               | Cria instância Carbon para data atual                      |
| [`trait_uses_recursive()`](#trait-uses-recursive) | Retorna traits usados por um trait                         |
| [`trans()`](#trans)                               | Traduz mensagem                                            |
| [`trans_choice()`](#trans-choice)                 | Traduz mensagem baseada em contagem                        |
| [`transform()`](#transform)                       | Transforma valor se estiver presente                       |
| [`url()`](#url)                                   | Gera URL para aplicação                                    |
| [`validator()`](#validator)                       | Cria instância Validator                                   |
| [`value()`](#value)                               | Retorna valor padrão (resolve Closures)                    |
| [`view()`](#view)                                 | Obtém conteúdo da view avaliada                            |
| [`when()`](#when)                                 | Retorna valor se condição for verdadeira                   |
| [`windows_os()`](#windows-os)                     | Verifica se ambiente é baseado em Windows                  |
| [`with()`](#with)                                 | Retorna valor passado através de callback                  |

---

## Helpers por Categoria

### Assets e Mix

#### `fake()`

Obtém uma instância do faker para testes e geração de dados fictícios.

```php
// Gerar nome falso
$nome = fake()->name();

// Gerar email falso
$email = fake()->email();

// Gerar texto falso
$texto = fake()->text(200);
```

#### `mix()`

Obtém o caminho para um arquivo versionado do Laravel Mix, incluindo o hash de versão para cache busting.

```php
// Caminho para arquivo CSS versionado
echo mix('css/app.css'); // /css/app.css?id=abc123

// Caminho para arquivo JS versionado
echo mix('js/app.js'); // /js/app.js?id=def456
```

### Autenticação e Autorização

#### `auth()`

Obtém a instância de autenticação disponível ou um guard específico.

```php
// Obter usuário autenticado
$user = auth()->user();

// Verificar se está autenticado
if (auth()->check()) {
    // Usuário está logado
}

// Usar guard específico
$admin = auth('admin')->user();
```

#### `policy()`

Obtém uma instância de policy para uma classe fornecida.

```php
// Obter policy para modelo Post
$policy = policy(Post::class);

// Verificar permissão
if ($policy->update($user, $post)) {
    // Usuário pode atualizar o post
}
```

### Caminhos do Sistema

#### `app_path()`

Obtém o caminho para a pasta da aplicação com possibilidade de especificar um arquivo ou subpasta.

```php
// Caminho da pasta app
echo app_path(); // /caminho/para/app

// Caminho para arquivo específico
echo app_path('Models/User.php'); // /caminho/para/app/Models/User.php

// Caminho para subpasta
echo app_path('Http/Controllers'); // /caminho/para/app/Http/Controllers
```

#### `base_path()`

Obtém o caminho para a base da instalação do Laravel.

```php
// Caminho base do projeto
echo base_path(); // /caminho/para/projeto

// Caminho para composer.json
echo base_path('composer.json'); // /caminho/para/projeto/composer.json
```

#### `config_path()`

Obtém o caminho para a pasta de configuração.

```php
// Caminho da pasta config
echo config_path(); // /caminho/para/config

// Caminho para arquivo específico
echo config_path('services.php'); // /caminho/para/config/services.php
```

#### `database_path()`

Obtém o caminho para a pasta do banco de dados.

```php
// Caminho da pasta database
echo database_path(); // /caminho/para/database

// Caminho para migrations
echo database_path('migrations'); // /caminho/para/database/migrations
```

#### `lang_path()`

Obtém o caminho para a pasta de idiomas/traduções.

```php
// Caminho da pasta lang
echo lang_path(); // /caminho/para/lang

// Caminho para idioma específico
echo lang_path('pt'); // /caminho/para/lang/pt
```

#### `public_path()`

Obtém o caminho para a pasta pública.

```php
// Caminho da pasta public
echo public_path(); // /caminho/para/public

// Caminho para arquivo específico
echo public_path('images/logo.png'); // /caminho/para/public/images/logo.png
```

#### `resource_path()`

Obtém o caminho para a pasta de recursos.

```php
// Caminho da pasta resources
echo resource_path(); // /caminho/para/resources

// Caminho para views
echo resource_path('views'); // /caminho/para/resources/views
```

#### `storage_path()`

Obtém o caminho para a pasta de armazenamento.

```php
// Caminho da pasta storage
echo storage_path(); // /caminho/para/storage

// Caminho para uploads
echo storage_path('app/uploads'); // /caminho/para/storage/app/uploads
```

### Configuração e Ambiente

#### `append_config()`

Atribui IDs numéricos altos a itens de configuração para forçar anexação.

```php
// Anexar configurações
append_config(['item1', 'item2']);

// Anexar array associativo
append_config([
    'services.custom' => 'value1',
    'app.providers' => 'MyProvider'
]);
```

#### `config()`

Obtém ou define valores de configuração especificados.

```php
// Obter configuração
$appName = config('app.name');

// Obter com valor padrão
$debug = config('app.debug', false);

// Definir configuração
config(['app.name' => 'Minha App']);

// Definir múltiplas configurações
config([
    'app.name' => 'Nova App',
    'app.env' => 'production'
]);
```

#### `env()`

Obtém o valor de uma variável de ambiente com possibilidade de valor padrão.

```php
// Obter variável de ambiente
$appName = env('APP_NAME');

// Com valor padrão
$debug = env('APP_DEBUG', false);

// Diferentes tipos
$port = env('DB_PORT', 3306);
$host = env('DB_HOST', 'localhost');
```

#### `laravel_cloud()`

Determina se a aplicação está rodando no Laravel Cloud.

```php
if (laravel_cloud()) {
    // Configurações específicas para Laravel Cloud
    $config = 'cloud-config';
} else {
    // Configurações para outros ambientes
    $config = 'local-config';
}
```

#### `windows_os()`

Determina se o ambiente atual é baseado em Windows.

```php
if (windows_os()) {
    // Comandos específicos para Windows
    $separator = '\\';
} else {
    // Comandos para Unix/Linux
    $separator = '/';
}
```

### Container e Dependências

#### `app()`

Obtém a instância do container da aplicação ou resolve um serviço específico.

```php
// Obter container
$app = app();

// Resolver serviço
$config = app('config');

// Resolver com parâmetros
$service = app('App\Services\CustomService');

// Verificar se está bound
if (app()->bound('custom.service')) {
    $service = app('custom.service');
}
```

#### `resolve()`

Resolve um serviço ou classe do container de dependências.

```php
// Resolver classe
$service = resolve('App\Services\PaymentService');

// Resolver interface
$repository = resolve('App\Contracts\UserRepositoryInterface');

// Resolver com parâmetros
$service = resolve('App\Services\CustomService', [
    'parameter' => 'value'
]);
```

### Controle de Fluxo

#### `once()`

Garante que um callable seja chamado apenas uma vez, retornando o resultado em chamadas subsequentes.

```php
// Operação custosa executada apenas uma vez
$result = once(function () {
    return expensive_database_query();
});

// Chamadas subsequentes retornam o mesmo resultado
$sameResult = once(function () {
    return expensive_database_query();
});
```

#### `retry()`

Tenta executar uma operação um determinado número de vezes antes de falhar.

```php
// Tentar 3 vezes
$result = retry(3, function () {
    return api_call_that_might_fail();
});

// Com delay entre tentativas (em milissegundos)
$result = retry(3, function () {
    return api_call();
}, 1000);

// Com callback para decidir se deve tentar novamente
$result = retry(3, function () {
    return api_call();
}, 0, function ($exception) {
    return $exception instanceof ConnectionException;
});
```

#### `tap()`

Chama o Closure fornecido com o valor e retorna o valor original.

```php
// Executar ação sem alterar o valor
$user = tap(new User(['name' => 'João']), function ($user) {
    $user->save();
    $user->assignRole('user');
});

// Com objetos existentes
$collection = tap(collect([1, 2, 3]), function ($collection) {
    $collection->push(4);
    log('Collection modified');
});
```

#### `transform()`

Transforma o valor fornecido se estiver presente (não nulo), caso contrário retorna o valor original.

```php
// Transformar se não for null
$result = transform($value, function ($v) {
    return strtoupper($v);
});

// Com valor padrão
$result = transform($value, function ($v) {
    return strtoupper($v);
}, 'DEFAULT');

// Exemplo prático
$name = transform($user->name ?? null, function ($name) {
    return ucwords($name);
}, 'Usuário Anônimo');
```

#### `value()`

Retorna o valor padrão do valor fornecido, resolvendo Closures automaticamente.

```php
// Valor simples
$result = value('hello'); // 'hello'

// Resolver Closure
$result = value(function () {
    return 'computed value';
}); // 'computed value'

// Com parâmetros
$result = value(function ($prefix) {
    return $prefix . ' world';
}, 'hello'); // 'hello world'
```

#### `when()`

Retorna um valor se a condição fornecida for verdadeira, caso contrário retorna um valor alternativo.

```php
// Condição simples
$message = when($user, 'Usuário logado', 'Visitante');

// Com Closures
$result = when($condition, function () {
    return expensive_operation();
}, function () {
    return default_value();
});

// Valor único
$class = when($isActive, 'active');
```

#### `with()`

Retorna o valor fornecido, opcionalmente passado através de um callback.

```php
// Sem callback
$user = with(new User());

// Com callback
$name = with($user, function ($user) {
    return $user->name;
});

// Encadeamento
$result = with(collect([1, 2, 3]), function ($collection) {
    return $collection->map(function ($item) {
        return $item * 2;
    });
});
```

### Data e Tempo

#### `now()`

Cria uma nova instância Carbon para o tempo atual com possibilidade de especificar timezone.

```php
// Data/hora atual
$now = now();

// Com timezone específico
$saoPaulo = now('America/Sao_Paulo');
$utc = now('UTC');

// Formatação
echo now()->format('Y-m-d H:i:s');

// Operações
$futuro = now()->addDays(7);
$passado = now()->subHours(2);
```

#### `today()`

Cria uma nova instância Carbon para a data atual (meia-noite).

```php
// Data atual (00:00:00)
$today = today();

// Com timezone
$todaySP = today('America/Sao_Paulo');

// Comparações
if ($date->isToday()) {
    echo 'É hoje!';
}

// Operações
$tomorrow = today()->addDay();
$yesterday = today()->subDay();
```

### HTTP e Respostas

#### `abort()`

Lança uma HttpException com os dados fornecidos, interrompendo a execução.

```php
// Erro 404 simples
abort(404);

// Com mensagem personalizada
abort(404, 'Página não encontrada');

// Com headers personalizados
abort(403, 'Acesso negado', [
    'X-Custom-Header' => 'valor'
]);
```

#### `abort_if()`

Lança uma HttpException se a condição fornecida for verdadeira.

```php
// Verificar permissão
abort_if(!$user, 403, 'Acesso negado');

// Verificar propriedade
abort_if($post->user_id !== auth()->id(), 403);

// Com múltiplas condições
abort_if(!$user || !$user->isActive(), 401, 'Usuário inativo');
```

#### `abort_unless()`

Lança uma HttpException a menos que a condição seja verdadeira.

```php
// Verificar autenticação
abort_unless(auth()->check(), 401);

// Verificar permissão de admin
abort_unless($user->isAdmin(), 403, 'Apenas administradores');

// Verificar status
abort_unless($post->isPublished(), 404);
```

#### `back()`

Cria uma nova resposta de redirecionamento para a localização anterior do usuário.

```php
// Redirecionamento simples
return back();

// Com dados de sessão
return back()->with('success', 'Operação realizada com sucesso!');

// Com erros
return back()->withErrors(['email' => 'Email inválido']);

// Com input antigo
return back()->withInput();
```

#### `redirect()`

Obtém uma instância do redirecionador para criar redirecionamentos.

```php
// Redirecionamento simples
return redirect('/home');

// Para rota nomeada
return redirect()->route('dashboard');

// Com parâmetros
return redirect()->route('user.profile', ['id' => 1]);

// Com dados de sessão
return redirect('/home')->with('message', 'Bem-vindo!');
```

#### `response()`

Retorna uma nova resposta da aplicação com conteúdo e headers customizados.

```php
// Resposta JSON
return response()->json(['status' => 'success']);

// Com status code
return response('Conteúdo', 200);

// Com headers
return response()->json($data)->header('X-Custom', 'value');

// Download de arquivo
return response()->download($pathToFile);
```

#### `to_route()`

Cria uma nova resposta de redirecionamento para uma rota nomeada.

```php
// Redirecionamento para rota
return to_route('dashboard');

// Com parâmetros
return to_route('user.show', ['user' => 1]);

// Com query string
return to_route('posts.index', ['page' => 2]);
```

### Jobs e Eventos

#### `broadcast()`

Inicia a transmissão de um evento para canais de broadcasting.

```php
// Broadcast simples
broadcast(new OrderShipped($order));

// Para canais específicos
broadcast(new OrderShipped($order))->toOthers();

// Para canal privado
broadcast(new OrderShipped($order))->to('private-orders');
```

#### `defer()`

Adia a execução do callback fornecido até o final do ciclo de vida da requisição.

```php
// Operação diferida
defer(function () {
    Log::info('Requisição processada');
});

// Limpeza de recursos
defer(function () use ($tempFile) {
    unlink($tempFile);
});

// Com múltiplas operações
defer(function () {
    cleanup_cache();
    send_analytics();
});
```

#### `dispatch()`

Despacha um job para seu manipulador apropriado (fila ou execução imediata).

```php
// Despachar job simples
dispatch(new ProcessOrder($order));

// Com delay
dispatch(new SendEmail($user))->delay(now()->addMinutes(5));

// Para fila específica
dispatch(new ProcessPayment($payment))->onQueue('payments');
```

#### `dispatch_sync()`

Despacha um comando para seu manipulador no processo atual (execução síncrona).

```php
// Execução imediata
dispatch_sync(new ProcessOrder($order));

// Para operações que devem ser executadas imediatamente
dispatch_sync(new ValidateData($data));
```

#### `event()`

Despacha um evento e chama todos os listeners registrados.

```php
// Evento simples
event(new UserRegistered($user));

// Com múltiplos parâmetros
event(new OrderProcessed($order, $payment));

// Evento inline
event('user.login', [$user]);
```

### Logs e Contexto

#### `context()`

Obtém ou define valores de contexto especificados para logs estruturados.

```php
// Definir contexto
context('user_id', auth()->id());
context('request_id', Str::uuid());

// Obter contexto
$userId = context('user_id');

// Múltiplos valores
context([
    'user_id' => auth()->id(),
    'ip' => request()->ip()
]);
```

#### `info()`

Escreve informações no log com nível "info".

```php
// Log simples
info('Usuário fez login');

// Com contexto
info('Operação concluída', [
    'user_id' => 1,
    'duration' => 150
]);

// Com dados estruturados
info('API call made', [
    'endpoint' => '/api/users',
    'response_time' => 250
]);
```

#### `logger()`

Registra uma mensagem de debug nos logs ou retorna a instância do logger.

```php
// Mensagem de debug
logger('Debug information', ['data' => $debugData]);

// Obter instância do logger
$log = logger();
$log->error('Erro crítico');

// Diferentes níveis
logger()->info('Informação');
logger()->warning('Aviso');
logger()->error('Erro');
```

#### `logs()`

Obtém uma instância do driver de log especificado.

```php
// Driver padrão
$log = logs();

// Driver específico
$slackLog = logs('slack');
$fileLog = logs('single');

// Usar driver específico
logs('slack')->critical('Sistema com problemas');
```

### Manipulação de Arrays e Collections

#### `collect()`

Cria uma collection a partir do valor fornecido para manipulação fluente de dados.

```php
// Array simples
$collection = collect([1, 2, 3, 4]);

// Com objetos
$users = collect(User::all());

// Manipulação fluente
$result = collect([1, 2, 3])
    ->map(fn($i) => $i * 2)
    ->filter(fn($i) => $i > 4)
    ->values();
```

#### `data_fill()`

Preenche dados onde estão faltando usando notação de ponto.

```php
$data = ['user' => ['name' => 'João']];

// Preencher campo faltante
data_fill($data, 'user.email', 'joao@email.com');

// Múltiplos campos
data_fill($data, [
    'user.age' => 30,
    'user.city' => 'São Paulo'
]);

// Resultado: ['user' => ['name' => 'João', 'email' => 'joao@email.com']]
```

#### `data_forget()`

Remove/desdefine um item de array ou objeto usando notação de ponto.

```php
$data = [
    'user' => [
        'name' => 'João',
        'email' => 'joao@email.com',
        'password' => 'secret'
    ]
];

// Remover campo específico
data_forget($data, 'user.password');

// Remover múltiplos campos
data_forget($data, ['user.email', 'user.password']);
```

#### `data_get()`

Obtém um item de array ou objeto usando notação de ponto com valor padrão opcional.

```php
$data = [
    'user' => [
        'profile' => [
            'name' => 'João Silva'
        ]
    ]
];

// Obter valor aninhado
$name = data_get($data, 'user.profile.name'); // 'João Silva'

// Com valor padrão
$age = data_get($data, 'user.profile.age', 25); // 25

// Array de arrays
$names = data_get($users, '*.name');
```

#### `data_set()`

Define um item em array ou objeto usando notação de ponto.

```php
$data = [];

// Definir valor aninhado
data_set($data, 'user.profile.name', 'João Silva');

// Resultado: ['user' => ['profile' => ['name' => 'João Silva']]]

// Sobrescrever valor existente
data_set($data, 'user.profile.age', 30);

// Com arrays
data_set($data, 'user.hobbies.0', 'Programação');
```

#### `head()`

Obtém o primeiro elemento de um array, útil para encadeamento de métodos.

```php
// Array simples
$first = head([1, 2, 3]); // 1

// Com collection
$firstUser = head(User::all());

// Encadeamento
$result = head(
    collect($data)->where('status', 'active')->toArray()
);
```

#### `last()`

Obtém o último elemento de um array.

```php
// Array simples
$last = last([1, 2, 3]); // 3

// Com strings
$lastChar = last(str_split('hello')); // 'o'

// Array associativo
$lastValue = last(['a' => 1, 'b' => 2, 'c' => 3]); // 3
```

### Manipulação de Classes

#### `class_basename()`

Obtém o nome base da classe de um objeto ou string de classe.

```php
// De string
$basename = class_basename('App\Models\User'); // 'User'

// De objeto
$user = new User();
$basename = class_basename($user); // 'User'

// Namespace complexo
$basename = class_basename('App\Http\Controllers\UserController'); // 'UserController'
```

#### `class_uses_recursive()`

Retorna todos os traits usados por uma classe, suas classes pai e traits dos traits.

```php
// Obter todos os traits
$traits = class_uses_recursive(User::class);

// Verificar se usa trait específico
if (in_array('Notifiable', class_uses_recursive(User::class))) {
    // Classe usa o trait Notifiable
}

// Com instância
$traits = class_uses_recursive($user);
```

#### `trait_uses_recursive()`

Retorna todos os traits usados por um trait e seus traits dependentes.

```php
// Traits de um trait
$traits = trait_uses_recursive('App\Traits\Cacheable');

// Verificar dependências
$dependencies = trait_uses_recursive('Illuminate\Notifications\Notifiable');
```

### Manipulação de Dados

#### `cookie()`

Cria uma nova instância de cookie com configurações personalizadas.

```php
// Cookie simples
$cookie = cookie('name', 'value', 60); // 60 minutos

// Com configurações avançadas
$cookie = cookie('preferences', json_encode($prefs), 60 * 24 * 30, '/', null, true, true);

// Cookie de sessão
$sessionCookie = cookie('session_data', $data);

// Em resposta
return response('OK')->cookie($cookie);
```

#### `fluent()`

Cria um objeto Fluent a partir de um array ou objeto para acesso fluente aos dados.

```php
// De array
$fluent = fluent(['name' => 'João', 'age' => 30]);
echo $fluent->name; // 'João'

// Modificação fluente
$fluent->email = 'joao@email.com';

// Métodos encadeados
$data = fluent($array)->toArray();
```

#### `literal()`

Retorna um objeto literal/anônimo usando argumentos nomeados.

```php
// Objeto literal
$obj = literal(nome: 'João', idade: 30, ativo: true);

// Acesso a propriedades
echo $obj->nome; // 'João'
echo $obj->idade; // 30

// Uso em retornos
return literal(
    status: 'success',
    data: $processedData,
    timestamp: now()
);
```

#### `object_get()`

Obtém um item de um objeto usando notação de ponto.

```php
$obj = (object) [
    'user' => (object) [
        'profile' => (object) [
            'name' => 'João'
        ]
    ]
];

// Acesso aninhado
$name = object_get($obj, 'user.profile.name'); // 'João'

// Com valor padrão
$age = object_get($obj, 'user.profile.age', 25); // 25
```

#### `optional()`

Fornece acesso seguro a objetos opcionais, evitando erros de null.

```php
// Acesso seguro
$name = optional($user)->name;

// Método aninhado
$email = optional($user->profile)->email;

// Com callback
$result = optional($user, function ($user) {
    return $user->profile->getDisplayName();
});

// Evita erros
$city = optional($user->address)->city; // null se address for null
```

### Requisições e Views

#### `precognitive()`

Manipula um hook de controller Precognition para validação antecipada.

```php
// Hook básico
return precognitive(function ($when) {
    $when(request()->missing('user_id'), function () {
        return response()->json(['errors' => ['user_id' => 'Required']]);
    });
});

// Validação condicional
return precognitive(function ($when) {
    $when(request()->filled('email'), function () {
        // Validar email apenas se fornecido
        validator(request()->all(), ['email' => 'email'])->validate();
    });
});
```

#### `request()`

Obtém uma instância da requisição atual ou um item de entrada específico.

```php
// Instância completa
$request = request();

// Item específico
$email = request('email');

// Com valor padrão
$page = request('page', 1);

// Múltiplos itens
$data = request(['name', 'email', 'phone']);

// Verificações
if (request()->has('search')) {
    $search = request('search');
}
```

#### `validator()`

Cria uma nova instância Validator para validação de dados.

```php
// Validação básica
$validator = validator($data, [
    'name' => 'required|string|max:255',
    'email' => 'required|email|unique:users'
]);

// Verificar se passou
if ($validator->passes()) {
    // Validação passou
}

// Obter erros
$errors = $validator->errors();

// Mensagens personalizadas
$validator = validator($data, $rules, [
    'name.required' => 'O nome é obrigatório'
]);
```

#### `view()`

Obtém o conteúdo da view avaliada com dados opcionais.

```php
// View simples
return view('welcome');

// Com dados
return view('user.profile', ['user' => $user]);

// Dados múltiplos
return view('dashboard', compact('users', 'posts', 'stats'));

// View aninhada
return view('admin.users.index', $data);

// Verificar se existe
if (view()->exists('custom.template')) {
    return view('custom.template');
}
```

### Segurança e Criptografia

#### `bcrypt()`

Faz hash do valor fornecido usando o algoritmo bcrypt para senhas seguras.

```php
// Hash de senha
$hashedPassword = bcrypt('minha-senha-segura');

// Verificação posterior com Hash::check()
if (Hash::check('minha-senha-segura', $hashedPassword)) {
    // Senha correta
}

// Em modelos
public function setPasswordAttribute($value)
{
    $this->attributes['password'] = bcrypt($value);
}
```

#### `csrf_field()`

Gera um campo de formulário HTML hidden com token CSRF para proteção.

```php
// Em blade templates
{!! csrf_field() !!}

// Resultado HTML
// <input type="hidden" name="_token" value="abc123...">

// Em formulários manuais
echo '<form method="POST">';
echo csrf_field();
echo '<input type="text" name="data">';
echo '</form>';
```

#### `csrf_token()`

Obtém o valor do token CSRF atual da sessão.

```php
// Obter token
$token = csrf_token();

// Em JavaScript/AJAX
$token = csrf_token();
echo "<script>window.csrfToken = '{$token}';</script>";

// Em meta tags
echo '<meta name="csrf-token" content="' . csrf_token() . '">';
```

#### `decrypt()`

Descriptografa o valor fornecido usando a chave da aplicação.

```php
// Descriptografar dados
$decrypted = decrypt($encryptedValue);

// Com tratamento de erro
try {
    $data = decrypt($encryptedData);
} catch (DecryptException $e) {
    // Falha na descriptografia
}

// Dados complexos
$array = decrypt($encryptedArray);
$object = decrypt($encryptedObject);
```

#### `e()`

Codifica caracteres especiais HTML em uma string para prevenir ataques XSS.

```php
// Escapar conteúdo perigoso
$safe = e('<script>alert("xss")</script>');
// Resultado: &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;

// Em templates
echo e($userInput);

// Dados do usuário
$comment = e($request->input('comment'));
echo "Comentário: {$comment}";
```

#### `encrypt()`

Criptografa o valor fornecido usando a chave da aplicação.

```php
// Criptografar dados sensíveis
$encrypted = encrypt('dados-confidenciais');

// Arrays e objetos
$encryptedArray = encrypt(['credit_card' => '1234-5678-9012-3456']);

// Para armazenamento
$user->encrypted_data = encrypt($sensitiveData);
$user->save();
```

#### `method_field()`

Gera um campo de formulário para falsificar o verbo HTTP (PUT, PATCH, DELETE).

```php
// Para métodos não suportados por HTML
echo method_field('PUT');
// <input type="hidden" name="_method" value="PUT">

// Em formulários
echo '<form method="POST">';
echo method_field('DELETE');
echo csrf_field();
echo '</form>';

// Em Blade
@method('PATCH')
```

### Sessão e Cache

#### `cache()`

Obtém ou define valores do cache especificado com TTL opcional.

```php
// Obter do cache
$value = cache('key');

// Com valor padrão
$value = cache('key', 'default');

// Definir no cache
cache(['key' => 'value'], 60); // 60 minutos

// Cache permanente
cache()->forever('key', 'value');

// Cache com callback
$users = cache('users', function () {
    return User::all();
});
```

#### `old()`

Recupera um item de entrada antigo da sessão (geralmente após redirecionamento com erro).

```php
// Input anterior
$email = old('email');

// Com valor padrão
$name = old('name', 'Valor padrão');

// Em formulários
echo '<input type="email" value="' . old('email') . '">';

// Arrays
$hobbies = old('hobbies', []);
```

#### `session()`

Obtém ou define valores de sessão especificados.

```php
// Obter da sessão
$userId = session('user_id');

// Com valor padrão
$theme = session('theme', 'light');

// Definir na sessão
session(['user_id' => 123]);

// Flash data (apenas próxima requisição)
session()->flash('message', 'Sucesso!');

// Múltiplos valores
session([
    'user_id' => 123,
    'role' => 'admin'
]);
```

### Strings e Regex

#### `preg_replace_array()`

Substitui um padrão com cada valor do array sequencialmente.

```php
// Substituição sequencial
$result = preg_replace_array('/\?/', ['João', 'Silva'], 'Nome: ? Sobrenome: ?');
// Resultado: 'Nome: João Sobrenome: Silva'

// Com múltiplas substituições
$template = 'SELECT * FROM ? WHERE ? = ?';
$query = preg_replace_array('/\?/', ['users', 'id', '1'], $template);
// Resultado: 'SELECT * FROM users WHERE id = 1'

// Dados dinâmicos
$values = ['produto', 'ativo', '1'];
$sql = preg_replace_array('/\?/', $values, 'SELECT * FROM ? WHERE ? = ?');
```

#### `str()`

Obtém um novo objeto stringable da string fornecida para manipulação fluente.

```php
// Manipulação fluente
$result = str('hello world')
    ->upper()
    ->replace('WORLD', 'LARAVEL')
    ->toString(); // 'HELLO LARAVEL'

// Métodos encadeados
$slug = str('Meu Título de Post')
    ->slug()
    ->toString(); // 'meu-titulo-de-post'

// Verificações
if (str($email)->contains('@')) {
    // É um email válido
}

// Conversões
$camel = str('hello_world')->camel(); // 'helloWorld'
$snake = str('HelloWorld')->snake(); // 'hello_world'
```

### Tradução

#### `__()`

Traduz a mensagem fornecida (alias para trans) usando os arquivos de idioma.

```php
// Tradução simples
echo __('messages.welcome'); // 'Bem-vindo'

// Com parâmetros
echo __('messages.hello', ['name' => 'João']); // 'Olá, João'

// Idioma específico
echo __('messages.goodbye', [], 'en'); // 'Goodbye'

// Com valor padrão
echo __('messages.unknown', [], 'pt', 'Mensagem não encontrada');
```

#### `trans()`

Traduz a mensagem fornecida usando os arquivos de tradução.

```php
// Tradução básica
$message = trans('messages.welcome');

// Com substituições
$greeting = trans('messages.hello', ['name' => $user->name]);

// Arquivo específico
$error = trans('validation.required', ['attribute' => 'email']);

// Namespace de package
$text = trans('package::messages.title');
```

#### `trans_choice()`

Traduz a mensagem baseada em uma contagem (pluralização).

```php
// Pluralização
$message = trans_choice('messages.apples', $count);
// 0: 'no apples', 1: '1 apple', 2+: '2 apples'

// Com substituições
$text = trans_choice('messages.items', $count, ['count' => $count]);

// Regras complexas
$result = trans_choice('messages.comments', $commentCount, [
    'count' => $commentCount,
    'user' => $user->name
]);
```

### Tratamento de Erros

#### `report()`

Reporta uma exceção para o sistema de logging/monitoramento.

```php
// Reportar exceção
try {
    risky_operation();
} catch (Exception $e) {
    report($e);
    // Continuar execução
}

// Reportar erro customizado
report(new CustomException('Algo deu errado'));

// Com contexto adicional
report($exception, ['user_id' => auth()->id()]);
```

#### `report_if()`

Reporta uma exceção se a condição fornecida for verdadeira.

```php
// Reportar condicionalmente
report_if($shouldLog, $exception);

// Com condições complexas
report_if(
    app()->environment('production') && $error->isCritical(),
    $error
);

// Baseado em configuração
report_if(config('app.debug'), new DebugException($data));
```

#### `report_unless()`

Reporta uma exceção a menos que a condição seja verdadeira.

```php
// Reportar a menos que seja desenvolvimento
report_unless(app()->environment('local'), $exception);

// Reportar a menos que seja ignorável
report_unless($error->isIgnorable(), $error);

// Com múltiplas condições
report_unless(
    $user->isAdmin() || app()->environment('testing'),
    $securityException
);
```

#### `rescue()`

Captura uma exceção potencial e retorna um valor padrão.

```php
// Operação arriscada com fallback
$result = rescue(function () {
    return external_api_call();
}, 'valor padrão');

// Com callback de erro
$data = rescue(function () {
    return parse_json($invalidJson);
}, function ($exception) {
    logger()->error('JSON parsing failed', ['error' => $exception->getMessage()]);
    return [];
});

// Operações de banco
$user = rescue(function () {
    return User::findOrFail($id);
}, new User());
```

#### `throw_if()`

Lança uma exceção se a condição fornecida for verdadeira.

```php
// Validação simples
throw_if($errors->any(), 'Erro de validação encontrado');

// Com exceção específica
throw_if(!$user, new UserNotFoundException());

// Condições múltiplas
throw_if(
    !$user || !$user->isActive(),
    new UnauthorizedException('Usuário inativo')
);

// Com dados
throw_if($quota->exceeded(), new QuotaExceededException([
    'current' => $quota->current,
    'limit' => $quota->limit
]));
```

#### `throw_unless()`

Lança uma exceção a menos que a condição seja verdadeira.

```php
// Verificar autorização
throw_unless(auth()->check(), new AuthenticationException());

// Verificar permissões
throw_unless(
    $user->can('update', $post),
    new AuthorizationException('Sem permissão para editar')
);

// Validação de negócio
throw_unless(
    $order->isPending(),
    new InvalidStateException('Pedido não pode ser modificado')
);
```

### URLs e Rotas

#### `action()`

Gera a URL para uma ação do controller especificada.

```php
// Ação básica
$url = action('UserController@show', ['id' => 1]);

// Com namespace
$url = action('App\Http\Controllers\UserController@show', ['user' => 1]);

// Método estático
$url = action([UserController::class, 'show'], ['user' => 1]);

// Com query string
$url = action('PostController@index', ['category' => 'tech']);
```

#### `asset()`

Gera um caminho de asset para a aplicação com versionamento automático.

```php
// Asset básico
echo asset('css/app.css'); // /css/app.css

// Com subpastas
echo asset('images/logos/brand.png'); // /images/logos/brand.png

// JavaScript
echo asset('js/app.js'); // /js/app.js

// Em views
<link rel="stylesheet" href="{{ asset('css/app.css') }}">
<script src="{{ asset('js/app.js') }}"></script>
```

#### `route()`

Gera a URL para uma rota nomeada com parâmetros opcionais.

```php
// Rota simples
$url = route('home'); // /

// Com parâmetros
$url = route('user.profile', ['user' => 1]); // /users/1

// Parâmetros nomeados
$url = route('posts.show', ['post' => $post->id, 'slug' => $post->slug]);

// Com query string
$url = route('posts.index', ['page' => 2]); // /posts?page=2
```

#### `secure_asset()`

Gera um caminho de asset com HTTPS forçado.

```php
// Asset seguro
echo secure_asset('css/app.css'); // https://exemplo.com/css/app.css

// Para CDN
echo secure_asset('images/logo.png'); // https://cdn.exemplo.com/images/logo.png

// Em ambientes mistos
if (request()->secure()) {
    $asset = secure_asset('js/app.js');
} else {
    $asset = asset('js/app.js');
}
```

#### `secure_url()`

Gera uma URL HTTPS para a aplicação.

```php
// URL segura
$url = secure_url('/admin'); // https://exemplo.com/admin

// Com parâmetros
$url = secure_url('/search', ['q' => 'laravel']); // https://exemplo.com/search?q=laravel

// API endpoints
$apiUrl = secure_url('/api/v1/users');
```

#### `url()`

Gera uma URL para a aplicação com caminho opcional.

```php
// URL base
$base = url(); // https://exemplo.com

// Com caminho
$profile = url('/profile'); // https://exemplo.com/profile

// Com parâmetros
$search = url('/search', ['q' => 'laravel']); // https://exemplo.com/search?q=laravel

// URL completa
$full = url()->full(); // URL atual completa
```

### Validação de Valores

#### `blank()`

Determina se um valor está "vazio" (null, string vazia, array vazio, etc.).

```php
// Valores vazios
blank('') // true
blank(null) // true
blank([]) // true
blank(collect()) // true

// Valores preenchidos
blank('texto') // false
blank(0) // false
blank([1, 2, 3]) // false

// Uso prático
if (blank($user->bio)) {
    $user->bio = 'Usuário ainda não adicionou uma biografia.';
}
```

#### `filled()`

Determina se um valor está "preenchido" (oposto de blank).

```php
// Valores preenchidos
filled('texto') // true
filled([1, 2, 3]) // true
filled(0) // true

// Valores vazios
filled('') // false
filled(null) // false
filled([]) // false

// Validação
if (filled($request->description)) {
    $post->description = $request->description;
}
```
