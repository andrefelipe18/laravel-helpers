# Laravel Helpers - Guía Completa

## Índice de Helpers

| Helper                                            | Descripción                                               |
| ------------------------------------------------- | --------------------------------------------------------- |
| [`__()`](#__)                                     | Traduce mensaje (alias para `trans()`)                    |
| [`abort()`](#abort)                               | Lanza `HttpException` con datos dados                     |
| [`abort_if()`](#abort-if)                         | Lanza `HttpException` si condición es verdadera           |
| [`abort_unless()`](#abort-unless)                 | Lanza `HttpException` a menos que condición sea verdadera |
| [`action()`](#action)                             | Genera URL para acción del controlador                    |
| [`app()`](#app)                                   | Obtiene instancia del contenedor                          |
| [`app_path()`](#app-path)                         | Obtiene ruta de la carpeta de aplicación                  |
| [`append_config()`](#append-config)               | Anexa elementos de configuración                          |
| [`asset()`](#asset)                               | Genera ruta de asset                                      |
| [`auth()`](#auth)                                 | Obtiene instancia de autenticación                        |
| [`back()`](#back)                                 | Redirección a página anterior                             |
| [`base_path()`](#base-path)                       | Obtiene ruta base de la instalación                       |
| [`bcrypt()`](#bcrypt)                             | Hace hash usando algoritmo `bcrypt`                       |
| [`blank()`](#blank)                               | Verifica si valor está vacío                              |
| [`broadcast()`](#broadcast)                       | Inicia transmisión de evento                              |
| [`cache()`](#cache)                               | Gestiona valores del caché                                |
| [`class_basename()`](#class-basename)             | Obtiene nombre base de la clase                           |
| [`class_uses_recursive()`](#class-uses-recursive) | Retorna traits usados recursivamente                      |
| [`collect()`](#collect)                           | Crea colección a partir de valor                          |
| [`config()`](#config)                             | Gestiona valores de configuración                         |
| [`config_path()`](#config-path)                   | Obtiene ruta de configuración                             |
| [`context()`](#context)                           | Gestiona contexto para logs                               |
| [`cookie()`](#cookie)                             | Crea instancia de cookie                                  |
| [`csrf_field()`](#csrf-field)                     | Genera campo de formulario CSRF                           |
| [`csrf_token()`](#csrf-token)                     | Obtiene token CSRF                                        |
| [`data_fill()`](#data-fill)                       | Rellena datos faltantes                                   |
| [`data_forget()`](#data-forget)                   | Elimina elemento por notación de punto                    |
| [`data_get()`](#data-get)                         | Obtiene elemento por notación de punto                    |
| [`data_set()`](#data-set)                         | Define elemento por notación de punto                     |
| [`database_path()`](#database-path)               | Obtiene ruta de la base de datos                          |
| [`decrypt()`](#decrypt)                           | Desencripta valor                                         |
| [`defer()`](#defer)                               | Aplaza ejecución de callback                              |
| [`dispatch()`](#dispatch)                         | Despacha job al manejador                                 |
| [`dispatch_sync()`](#dispatch-sync)               | Despacha comando en proceso actual                        |
| [`e()`](#e)                                       | Codifica caracteres HTML para prevenir XSS                |
| [`encrypt()`](#encrypt)                           | Encripta valor                                            |
| [`env()`](#env)                                   | Obtiene valor de variable de entorno                      |
| [`event()`](#event)                               | Despacha evento y llama listeners                         |
| [`fake()`](#fake)                                 | Obtiene instancia del faker para pruebas                  |
| [`filled()`](#filled)                             | Verifica si valor está rellenado                          |
| [`fluent()`](#fluent)                             | Crea objeto Fluent                                        |
| [`head()`](#head)                                 | Obtiene primer elemento del array                         |
| [`info()`](#info)                                 | Escribe información en el log                             |
| [`lang_path()`](#lang-path)                       | Obtiene ruta de la carpeta de idiomas                     |
| [`laravel_cloud()`](#laravel-cloud)               | Verifica si está ejecutándose en Laravel Cloud            |
| [`last()`](#last)                                 | Obtiene último elemento del array                         |
| [`literal()`](#literal)                           | Retorna objeto literal usando argumentos nombrados        |
| [`logger()`](#logger)                             | Registra mensaje de debug en los logs                     |
| [`logs()`](#logs)                                 | Obtiene instancia del driver de log                       |
| [`method_field()`](#method-field)                 | Genera campo para falsificar verbo HTTP                   |
| [`mix()`](#mix)                                   | Obtiene ruta para archivo versionado del Mix              |
| [`now()`](#now)                                   | Crea instancia Carbon para tiempo actual                  |
| [`object_get()`](#object-get)                     | Obtiene elemento de objeto por notación de punto          |
| [`old()`](#old)                                   | Recupera elemento de entrada antigua                      |
| [`once()`](#once)                                 | Garantiza ejecución única de callable                     |
| [`optional()`](#optional)                         | Acceso seguro a propiedades/métodos sin error de null     |
| [`policy()`](#policy)                             | Obtiene instancia de policy                               |
| [`precognitive()`](#precognitive)                 | Maneja hook del controlador Precognition                  |
| [`preg_replace_array()`](#preg-replace-array)     | Sustituye patrón con valores del array                    |
| [`public_path()`](#public-path)                   | Obtiene ruta de la carpeta pública                        |
| [`redirect()`](#redirect)                         | Obtiene instancia del redireccionador                     |
| [`report()`](#report)                             | Reporta excepción                                         |
| [`report_if()`](#report-if)                       | Reporta excepción si condición es verdadera               |
| [`report_unless()`](#report-unless)               | Reporta excepción a menos que condición sea verdadera     |
| [`request()`](#request)                           | Obtiene instancia de la petición actual                   |
| [`rescue()`](#rescue)                             | Captura excepción y retorna valor por defecto             |
| [`resolve()`](#resolve)                           | Resuelve servicio del contenedor                          |
| [`resource_path()`](#resource-path)               | Obtiene ruta de la carpeta de recursos                    |
| [`response()`](#response)                         | Retorna nueva respuesta de la aplicación                  |
| [`retry()`](#retry)                               | Intenta ejecutar operación múltiples veces                |
| [`route()`](#route)                               | Genera URL para ruta nombrada                             |
| [`secure_asset()`](#secure-asset)                 | Genera ruta de asset con HTTPS                            |
| [`secure_url()`](#secure-url)                     | Genera URL HTTPS                                          |
| [`session()`](#session)                           | Gestiona valores de sesión                                |
| [`storage_path()`](#storage-path)                 | Obtiene ruta de la carpeta de almacenamiento              |
| [`str()`](#str)                                   | Obtiene objeto stringable                                 |
| [`tap()`](#tap)                                   | Llama Closure con valor y retorna valor                   |
| [`throw_if()`](#throw-if)                         | Lanza excepción si condición es verdadera                 |
| [`throw_unless()`](#throw-unless)                 | Lanza excepción a menos que condición sea verdadera       |
| [`to_route()`](#to-route)                         | Crea redirección a ruta nombrada                          |
| [`today()`](#today)                               | Crea instancia Carbon para fecha actual                   |
| [`trait_uses_recursive()`](#trait-uses-recursive) | Retorna traits usados por un trait                        |
| [`trans()`](#trans)                               | Traduce mensaje                                           |
| [`trans_choice()`](#trans-choice)                 | Traduce mensaje basado en conteo                          |
| [`transform()`](#transform)                       | Transforma valor si está presente                         |
| [`url()`](#url)                                   | Genera URL para aplicación                                |
| [`validator()`](#validator)                       | Crea instancia Validator                                  |
| [`value()`](#value)                               | Retorna valor por defecto (resuelve Closures)             |
| [`view()`](#view)                                 | Obtiene contenido de la vista evaluada                    |
| [`when()`](#when)                                 | Retorna valor si condición es verdadera                   |
| [`windows_os()`](#windows-os)                     | Verifica si entorno está basado en Windows                |
| [`with()`](#with)                                 | Retorna valor pasado a través de callback                 |

---

## Helpers por Categoría

### Assets y Mix

#### `fake()`

Obtiene una instancia del faker para pruebas y generación de datos ficticios.

```php
// Generar nombre falso
$nombre = fake()->name();

// Generar email falso
$email = fake()->email();

// Generar texto falso
$texto = fake()->text(200);
```

#### `mix()`

Obtiene la ruta para un archivo versionado del Laravel Mix, incluyendo el hash de versión para cache busting.

```php
// Ruta para archivo CSS versionado
echo mix('css/app.css'); // /css/app.css?id=abc123

// Ruta para archivo JS versionado
echo mix('js/app.js'); // /js/app.js?id=def456
```

### Autenticación y Autorización

#### `auth()`

Obtiene la instancia de autenticación disponible o un guard específico.

```php
// Obtener usuario autenticado
$user = auth()->user();

// Verificar si está autenticado
if (auth()->check()) {
    // Usuario está logueado
}

// Usar guard específico
$admin = auth('admin')->user();
```

#### `policy()`

Obtiene una instancia de policy para autorización.

```php
// Obtener policy de usuario
$policy = policy(User::class);

// Verificar permiso
if ($policy->view($user, $post)) {
    // Usuario puede ver el post
}
```

### Generación de URL

#### `action()`

Genera una URL para una acción del controlador.

```php
// URL para acción del controlador
$url = action([UserController::class, 'show'], ['id' => 1]);
// /user/1

// URL con parámetros adicionales
$url = action([UserController::class, 'edit'], ['user' => 1], false);
// user/1/edit (URL relativa)
```

#### `asset()`

Genera una URL para un asset de la aplicación.

```php
// URL de asset
echo asset('css/app.css'); // /css/app.css

// Asset con subdominio
echo asset('images/logo.png'); // /images/logo.png
```

#### `route()`

Genera una URL para una ruta nombrada.

```php
// URL de ruta nombrada
$url = route('user.show', ['id' => 1]);

// Ruta con parámetros
$url = route('user.edit', ['user' => $user]);

// URL absoluta
$url = route('user.show', ['id' => 1], true);
```

#### `secure_asset()`

Genera una URL para un asset de la aplicación usando HTTPS.

```php
// URL de asset seguro
echo secure_asset('css/app.css'); // https://example.com/css/app.css
```

#### `secure_url()`

Genera una URL HTTPS completamente calificada para la aplicación.

```php
// URL segura
echo secure_url('user/profile'); // https://example.com/user/profile

// URL segura con parámetros
echo secure_url('user/profile', ['tab' => 'settings']);
```

#### `url()`

Genera una URL completamente calificada para la aplicación.

```php
// Generar URL
echo url('user/profile'); // http://example.com/user/profile

// URL con parámetros
echo url('user/profile', ['tab' => 'settings']);
// http://example.com/user/profile?tab=settings

// URL segura
echo url('user/profile', [], true); // https://example.com/user/profile
```

### Respuesta y Redirección

#### `abort()`

Lanza una excepción HTTP.

```php
// Error 404
abort(404);

// Error 403 con mensaje
abort(403, 'Acción no autorizada.');

// Error 500 con headers
abort(500, 'Error del Servidor', ['X-Custom-Header' => 'value']);
```

#### `abort_if()`

Lanza una excepción HTTP si una condición es verdadera.

```php
// Abortar si usuario no es admin
abort_if(!auth()->user()->isAdmin(), 403);

// Abortar con mensaje personalizado
abort_if($errors->any(), 422, 'Validación falló');
```

#### `abort_unless()`

Lanza una excepción HTTP a menos que una condición sea verdadera.

```php
// Abortar a menos que usuario sea propietario del post
abort_unless($user->owns($post), 403);

// Abortar a menos que esté autenticado
abort_unless(auth()->check(), 401, 'Autenticación requerida');
```

#### `back()`

Crea una respuesta de redirección a la ubicación anterior del usuario.

```php
// Redirigir atrás
return back();

// Redirigir atrás con datos
return back()->with('success', '¡Perfil actualizado!');

// Redirigir atrás con entrada
return back()->withInput();

// Redirigir atrás con errores
return back()->withErrors(['email' => 'Email inválido']);
```

#### `redirect()`

Obtiene una instancia del redireccionador.

```php
// Redirección simple
return redirect('/home');

// Redirigir a ruta nombrada
return redirect()->route('user.show', ['id' => 1]);

// Redirigir a acción del controlador
return redirect()->action([UserController::class, 'index']);

// Redirigir con datos
return redirect('/home')->with('success', '¡Bienvenido!');
```

#### `response()`

Retorna una nueva respuesta de la aplicación.

```php
// Respuesta simple
return response('Hola Mundo');

// Respuesta JSON
return response()->json(['message' => 'Éxito']);

// Respuesta con estado y headers
return response('No Encontrado', 404, ['Content-Type' => 'text/plain']);

// Respuesta de descarga
return response()->download('/path/to/file.pdf');
```

#### `to_route()`

Crea una respuesta de redirección a una ruta nombrada.

```php
// Redirigir a ruta nombrada
return to_route('user.show', ['id' => 1]);

// Redirigir con código de estado
return to_route('user.index', [], 302);
```

### Rutas de la Aplicación

#### `app_path()`

Obtiene la ruta a la carpeta de aplicación.

```php
// Ruta del directorio app
$path = app_path(); // /path/to/app

// Ruta a archivo específico
$path = app_path('Http/Controllers/UserController.php');
// /path/to/app/Http/Controllers/UserController.php
```

#### `base_path()`

Obtiene la ruta a la raíz del proyecto.

```php
// Ruta base
$path = base_path(); // /path/to/project

// Ruta a archivo específico
$path = base_path('composer.json'); // /path/to/project/composer.json
```

#### `config_path()`

Obtiene la ruta a la carpeta de configuración.

```php
// Ruta del directorio config
$path = config_path(); // /path/to/config

// Ruta a archivo de configuración específico
$path = config_path('app.php'); // /path/to/config/app.php
```

#### `database_path()`

Obtiene la ruta a la carpeta de base de datos.

```php
// Ruta del directorio database
$path = database_path(); // /path/to/database

// Ruta a archivo específico
$path = database_path('migrations'); // /path/to/database/migrations
```

#### `lang_path()`

Obtiene la ruta a la carpeta de idiomas.

```php
// Ruta del directorio lang
$path = lang_path(); // /path/to/lang

// Ruta a archivo de idioma específico
$path = lang_path('en/messages.php'); // /path/to/lang/en/messages.php
```

#### `public_path()`

Obtiene la ruta a la carpeta pública.

```php
// Ruta del directorio public
$path = public_path(); // /path/to/public

// Ruta a archivo específico
$path = public_path('css/app.css'); // /path/to/public/css/app.css
```

#### `resource_path()`

Obtiene la ruta a la carpeta de recursos.

```php
// Ruta del directorio resources
$path = resource_path(); // /path/to/resources

// Ruta a archivo específico
$path = resource_path('views/welcome.blade.php');
// /path/to/resources/views/welcome.blade.php
```

#### `storage_path()`

Obtiene la ruta a la carpeta de almacenamiento.

```php
// Ruta del directorio storage
$path = storage_path(); // /path/to/storage

// Ruta a archivo específico
$path = storage_path('app/file.txt'); // /path/to/storage/app/file.txt
```

### Contenedor y Servicios

#### `app()`

Obtiene la instancia del contenedor disponible o resuelve un servicio.

```php
// Obtener instancia de la aplicación
$app = app();

// Resolver servicio del contenedor
$cache = app('cache');

// Resolver con parámetros
$service = app(UserService::class, ['param' => 'value']);
```

#### `resolve()`

Resuelve un servicio del contenedor.

```php
// Resolver servicio
$cache = resolve('cache');

// Resolver clase
$service = resolve(UserService::class);
```

### Configuración

#### `config()`

Obtiene o establece valores de configuración.

```php
// Obtener valor de configuración
$timezone = config('app.timezone');

// Obtener con valor por defecto
$debug = config('app.debug', false);

// Establecer valor de configuración
config(['app.locale' => 'es']);

// Establecer múltiples valores
config([
    'app.timezone' => 'UTC',
    'app.locale' => 'es'
]);
```

#### `append_config()`

Anexa elementos de configuración a un valor de configuración de array.

```php
// Anexar a configuración de array
append_config(['app.providers' => [
    CustomServiceProvider::class
]]);
```

#### `env()`

Obtiene el valor de una variable de entorno.

```php
// Obtener variable de entorno
$debug = env('APP_DEBUG');

// Obtener con valor por defecto
$debug = env('APP_DEBUG', false);

// Variable de entorno con casting de tipo
$timeout = env('SESSION_LIFETIME', 120);
```

### Caché

#### `cache()`

Obtiene o almacena valores en el caché.

```php
// Obtener valor del caché
$value = cache('key');

// Obtener con valor por defecto
$value = cache('key', 'default');

// Almacenar en caché
cache(['key' => 'value'], now()->addHour());

// Almacenar con tags
cache()->tags(['users', 'posts'])->put('key', 'value', 3600);
```

### Sesión

#### `session()`

Obtiene o almacena valores de sesión.

```php
// Obtener valor de sesión
$value = session('key');

// Obtener con valor por defecto
$value = session('key', 'default');

// Almacenar en sesión
session(['key' => 'value']);

// Datos flash a sesión
session()->flash('message', '¡Éxito!');
```

#### `old()`

Recupera un valor de entrada flash de la sesión.

```php
// Obtener entrada antigua
$email = old('email');

// Obtener con valor por defecto
$name = old('name', 'Juan Pérez');

// En plantilla Blade
<input type="email" name="email" value="{{ old('email') }}">
```

### Cookies

#### `cookie()`

Crea una nueva instancia de cookie.

```php
// Crear cookie
$cookie = cookie('name', 'value', 60);

// Cookie con dominio y secure
$cookie = cookie('name', 'value', 60, '/', '.domain.com', true, true);

// Encolar cookie para próxima respuesta
cookie()->queue('name', 'value', 60);
```

### Protección CSRF

#### `csrf_field()`

Genera un campo de entrada HTML oculto que contiene el token CSRF.

```php
// En plantilla Blade
{{ csrf_field() }}

// Salida: <input type="hidden" name="_token" value="...">
```

#### `csrf_token()`

Obtiene el valor del token CSRF.

```php
// Obtener token CSRF
$token = csrf_token();

// En JavaScript
const token = '{{ csrf_token() }}';
```

#### `method_field()`

Genera un campo de entrada HTML oculto que contiene el verbo HTTP.

```php
// En plantilla Blade para petición PUT
{{ method_field('PUT') }}

// Salida: <input type="hidden" name="_method" value="PUT">

// Para petición DELETE
{{ method_field('DELETE') }}
```

### Petición e Entrada

#### `request()`

Obtiene la instancia de la petición actual o un valor de entrada.

```php
// Obtener instancia de petición
$request = request();

// Obtener valor de entrada
$email = request('email');

// Obtener con valor por defecto
$name = request('name', 'Invitado');

// Obtener toda la entrada
$input = request()->all();
```

### Validación

#### `validator()`

Crea una instancia de validador.

```php
// Crear validador
$validator = validator(['email' => 'test@example.com'], [
    'email' => 'required|email'
]);

// Verificar si la validación pasa
if ($validator->passes()) {
    // Validación pasó
}

// Obtener errores de validación
$errors = $validator->errors();
```

### Fecha y Hora

#### `now()`

Crea una instancia Carbon para la fecha y hora actual.

```php
// Timestamp actual
$now = now();

// Timestamp actual en zona horaria específica
$now = now('America/Mexico_City');

// Formatear hora actual
echo now()->format('Y-m-d H:i:s');

// Añadir tiempo
$future = now()->addHours(2);
```

#### `today()`

Crea una instancia Carbon para la fecha actual.

```php
// Fecha de hoy
$today = today();

// Hoy en zona horaria específica
$today = today('America/Mexico_City');

// Formatear fecha de hoy
echo today()->format('Y-m-d');

// Inicio del día
$startOfDay = today()->startOfDay();
```

### Localización

#### `__()`

Traduce el mensaje dado (alias para `trans()`).

```php
// Traducción simple
echo __('Bienvenido');

// Traducción con parámetros
echo __('Bienvenido, :name', ['name' => 'Juan']);

// Traducción de archivo específico
echo __('messages.welcome');

// Traducción con fallback
echo __('messages.welcome', [], 'en');
```

#### `trans()`

Traduce el mensaje dado.

```php
// Traducción simple
echo trans('Bienvenido');

// Traducción con parámetros
echo trans('Bienvenido, :name', ['name' => 'Juan']);

// Traducción de archivo específico
echo trans('messages.welcome');
```

#### `trans_choice()`

Traduce el mensaje dado basado en un conteo.

```php
// Pluralización
echo trans_choice('messages.notifications', $count);

// Con parámetros
echo trans_choice('messages.notifications', $count, ['name' => 'Juan']);

// Especificación manual de conteo
echo trans_choice('messages.items', 5, ['count' => 5]);
```

### Logging

#### `info()`

Escribe un mensaje informativo en los logs.

```php
// Log info simple
info('Usuario logueado');

// Info con contexto
info('Usuario logueado', ['user_id' => 123]);

// Info con datos adicionales
info('Procesando pago', [
    'amount' => 100,
    'currency' => 'USD',
    'user_id' => 123
]);
```

#### `logger()`

Registra un mensaje de debug en los logs u obtiene una instancia del logger.

```php
// Registrar mensaje de debug
logger('Información de debug');

// Registrar con contexto
logger('Acción de usuario', ['action' => 'login', 'user_id' => 123]);

// Obtener instancia del logger
$logger = logger();
$logger->error('Mensaje de error');
```

#### `logs()`

Obtiene una instancia del driver de log.

```php
// Obtener driver de log por defecto
$log = logs();

// Obtener driver específico
$slackLog = logs('slack');

// Registrar con driver específico
logs('slack')->info('Notificación importante');
```

#### `report()`

Reporta una excepción al manejador de excepciones.

```php
// Reportar excepción
try {
    // Código que podría fallar
} catch (Exception $e) {
    report($e);
}

// Reportar con contexto
report($exception, ['user_id' => auth()->id()]);
```

#### `report_if()`

Reporta una excepción si una condición dada es verdadera.

```php
// Reportar excepción si condición es verdadera
report_if($shouldReport, $exception);

// Reportar con contexto
report_if(app()->isProduction(), $exception, ['context' => 'production']);
```

#### `report_unless()`

Reporta una excepción a menos que una condición dada sea verdadera.

```php
// Reportar excepción a menos que condición sea verdadera
report_unless($shouldIgnore, $exception);

// Reportar a menos que esté en testing
report_unless(app()->runningUnitTests(), $exception);
```

### Eventos y Broadcasting

#### `broadcast()`

Comienza la transmisión de un evento.

```php
// Transmitir evento
broadcast(new OrderUpdated($order));

// Transmitir a canales específicos
broadcast(new OrderUpdated($order))->to(['order.' . $order->id]);

// Transmitir con retraso
broadcast(new OrderUpdated($order))->delay(now()->addMinutes(5));
```

#### `event()`

Despacha un evento y llama a sus listeners.

```php
// Despachar evento
event(new UserRegistered($user));

// Despachar con múltiples parámetros
event('user.login', [$user, $request]);

// Despachar hasta primera respuesta no nula
$response = event('user.login', [$user], true);
```

### Colas y Jobs

#### `dispatch()`

Despacha un job a su manejador apropiado.

```php
// Despachar job
dispatch(new ProcessPayment($order));

// Despachar con retraso
dispatch(new ProcessPayment($order))->delay(now()->addMinutes(10));

// Despachar a cola específica
dispatch(new ProcessPayment($order))->onQueue('payments');

// Despachar a conexión específica
dispatch(new ProcessPayment($order))->onConnection('redis');
```

#### `dispatch_sync()`

Despacha un comando a su manejador apropiado en el proceso actual.

```php
// Despachar sincrónicamente
dispatch_sync(new ProcessPayment($order));

// Útil para testing o ejecución inmediata
dispatch_sync(new SendWelcomeEmail($user));
```

### Seguridad

#### `bcrypt()`

Hace hash del valor dado usando el algoritmo bcrypt.

```php
// Hash de contraseña
$hash = bcrypt('password');

// Hash con rondas personalizadas
$hash = bcrypt('password', ['rounds' => 12]);

// Verificar contraseña
if (password_verify('password', $hash)) {
    // Contraseña es correcta
}
```

#### `decrypt()`

Desencripta el valor dado.

```php
// Desencriptar valor
$decrypted = decrypt($encryptedValue);

// Desencriptar con cipher específico
$decrypted = decrypt($encryptedValue, false);
```

#### `encrypt()`

Encripta el valor dado.

```php
// Encriptar valor
$encrypted = encrypt('datos secretos');

// Encriptar para serialización
$encrypted = encrypt($object, true);
```

#### `e()`

Codifica caracteres HTML en una cadena para prevenir ataques XSS.

```php
// Escapar HTML
echo e('<script>alert("XSS")</script>');
// Salida: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;

// Escapar entrada de usuario
echo e($userInput);

// En plantillas Blade (escape automático)
{{ $userInput }} // Automáticamente escapado
{!! $trustedInput !!} // No escapado
```

### Manipulación de Datos

#### `blank()`

Determina si el valor dado está "en blanco".

```php
// Verificar si está en blanco
blank(''); // true
blank(null); // true
blank([]); // true
blank(collect()); // true
blank('   '); // true
blank('hola'); // false
```

#### `filled()`

Determina si el valor dado no está "en blanco".

```php
// Verificar si está rellenado
filled('hola'); // true
filled([1, 2, 3]); // true
filled(''); // false
filled(null); // false
filled([]); // false
```

#### `collect()`

Crea una colección a partir del valor dado.

```php
// Crear colección de array
$collection = collect([1, 2, 3]);

// Crear colección vacía
$empty = collect();

// Métodos de colección
$collection->filter(function ($item) {
    return $item > 1;
})->map(function ($item) {
    return $item * 2;
});
```

#### `data_fill()`

Rellena valores faltantes en un array u objeto usando notación de punto.

```php
$data = ['products' => ['desk' => ['price' => 100]]];

// Rellenar valores faltantes
data_fill($data, 'products.desk.name', 'Escritorio');
data_fill($data, 'products.chair.price', 200);

// Resultado: ['products' => ['desk' => ['price' => 100, 'name' => 'Escritorio'], 'chair' => ['price' => 200]]]
```

#### `data_forget()`

Elimina un elemento de un array u objeto usando notación de punto.

```php
$data = [
    'products' => [
        'desk' => ['price' => 100, 'name' => 'Escritorio'],
        'chair' => ['price' => 200]
    ]
];

// Eliminar elemento
data_forget($data, 'products.desk.name');
data_forget($data, 'products.chair');
```

#### `data_get()`

Recupera un elemento de un array u objeto usando notación de punto.

```php
$data = [
    'products' => [
        'desk' => ['price' => 100, 'name' => 'Escritorio']
    ]
];

// Obtener elemento
$price = data_get($data, 'products.desk.price'); // 100
$name = data_get($data, 'products.desk.name'); // 'Escritorio'

// Obtener con valor por defecto
$color = data_get($data, 'products.desk.color', 'marrón'); // 'marrón'

// Usar comodín
$prices = data_get($data, 'products.*.price'); // [100]
```

#### `data_set()`

Establece un elemento en un array u objeto usando notación de punto.

```php
$data = ['products' => ['desk' => ['price' => 100]]];

// Establecer elemento
data_set($data, 'products.desk.name', 'Escritorio');
data_set($data, 'products.chair.price', 200);

// Establecer con comodín
data_set($data, 'products.*.discount', 10);
```

#### `head()`

Retorna el primer elemento en un array.

```php
// Obtener primer elemento
$first = head([1, 2, 3]); // 1
$first = head(['a' => 1, 'b' => 2]); // 1

// Array vacío
$first = head([]); // null
```

#### `last()`

Retorna el último elemento en un array.

```php
// Obtener último elemento
$last = last([1, 2, 3]); // 3
$last = last(['a' => 1, 'b' => 2]); // 2

// Array vacío
$last = last([]); // null
```

### Manipulación de Cadenas y Objetos

#### `class_basename()`

Obtiene el "basename" de clase del objeto / clase dado.

```php
// Obtener basename de clase
$basename = class_basename('App\Http\Controllers\UserController'); // 'UserController'
$basename = class_basename(new User); // 'User'
$basename = class_basename(User::class); // 'User'
```

#### `class_uses_recursive()`

Retorna todos los nombres de trait usados por una clase, sus clases padre y dependencias de traits.

```php
// Obtener todos los traits usados por clase
$traits = class_uses_recursive(User::class);

// Ejemplo de salida: ['Illuminate\Database\Eloquent\Concerns\HasTimestamps', ...]
```

#### `trait_uses_recursive()`

Retorna todos los nombres de trait usados por un trait y sus dependencias.

```php
// Obtener traits usados por un trait
$traits = trait_uses_recursive(SomeTraitName::class);
```

#### `fluent()`

Crea un objeto fluent a partir del valor dado.

```php
// Crear objeto fluent
$fluent = fluent(['name' => 'Juan', 'age' => 30]);

// Acceder propiedades
echo $fluent->name; // 'Juan'
echo $fluent->get('age'); // 30

// Establecer propiedades
$fluent->email = 'juan@example.com';
$fluent->set('phone', '123-456-7890');
```

#### `literal()`

Retorna un nuevo objeto con los argumentos nombrados dados.

```php
// Crear objeto con argumentos nombrados
$object = literal(name: 'Juan', age: 30, city: 'Madrid');

// Acceder propiedades
echo $object->name; // 'Juan'
echo $object->age; // 30
```

#### `object_get()`

Recupera un elemento de un objeto usando notación de punto.

```php
$object = (object) [
    'user' => (object) [
        'name' => 'Juan',
        'email' => 'juan@example.com'
    ]
];

// Obtener propiedad
$name = object_get($object, 'user.name'); // 'Juan'
$email = object_get($object, 'user.email'); // 'juan@example.com'

// Obtener con valor por defecto
$phone = object_get($object, 'user.phone', 'N/A'); // 'N/A'
```

#### `str()`

Obtiene un nuevo objeto stringable de la cadena dada.

```php
// Crear objeto stringable
$str = str('Hola Mundo');

// Manipulación de cadenas
$result = str('hola mundo')
    ->title()
    ->replace('Mundo', 'Laravel')
    ->slug();

// Encadenamiento de métodos
$slug = str('Hola Mundo')->slug(); // 'hola-mundo'
$title = str('hola mundo')->title(); // 'Hola Mundo'
```

### Control de Flujo

#### `once()`

Asegura que un callable se ejecute solo una vez.

```php
$expensive = once(function () {
    // Esta operación costosa solo se ejecutará una vez
    return expensiveOperation();
});

// Primera llamada ejecuta la función
$result1 = $expensive(); // Ejecuta expensiveOperation()

// Llamadas subsiguientes retornan resultado en caché
$result2 = $expensive(); // Retorna resultado en caché
```

#### `optional()`

Retorna el valor si existe o un valor por defecto.

```php
// Acceso seguro a propiedades
$name = optional($user)->name;

// Llamadas seguras a métodos
$email = optional($user)->getEmail();

// Llamadas encadenadas
$phone = optional($user)->profile->phone;

// Con callback
$result = optional($user, function ($user) {
    return $user->name . ' - ' . $user->email;
});
```

#### `rescue()`

Ejecuta el callback dado y captura cualquier excepción que ocurra durante la ejecución.

```php
// Rescue con valor por defecto
$result = rescue(function () {
    return riskyOperation();
}, 'valor por defecto');

// Rescue con callback para manejo de excepciones
$result = rescue(function () {
    return riskyOperation();
}, function ($exception) {
    report($exception);
    return 'valor de respaldo';
});

// Rescue simple
$result = rescue(fn() => $user->profile->phone, 'N/A');
```

#### `retry()`

Intenta ejecutar el callback dado hasta que se alcance el umbral máximo de intentos dado.

```php
// Reintentar hasta 3 veces
$result = retry(3, function () {
    // Operación potencialmente fallida
    return callExternalAPI();
});

// Reintentar con retraso (milisegundos)
$result = retry(3, function () {
    return callExternalAPI();
}, 1000);

// Reintentar con función de retraso personalizada
$result = retry(3, function () {
    return callExternalAPI();
}, function ($attempt) {
    return $attempt * 1000; // Backoff exponencial
});

// Reintentar con condición when
$result = retry(3, function () {
    return callExternalAPI();
}, 1000, function ($exception) {
    return $exception instanceof ConnectionException;
});
```

#### `tap()`

Llama el closure dado con el valor dado y luego retorna el valor.

```php
// Tap en valor
$user = tap(new User, function ($user) {
    $user->name = 'Juan';
    $user->email = 'juan@example.com';
});

// Tap con llamadas a métodos
$collection = tap(collect([1, 2, 3]), function ($collection) {
    $collection->push(4);
});

// Tap para debugging
$result = tap($someValue, function ($value) {
    logger('Procesando valor: ' . $value);
});
```

#### `throw_if()`

Lanza la excepción dada si una condición dada evalúa a verdadero.

```php
// Lanzar si condición es verdadera
throw_if($user->isNotAuthorized(), new UnauthorizedException);

// Lanzar con mensaje
throw_if($errors->any(), ValidationException::class, 'Validación falló');

// Lanzar con callback
throw_if($user->isBlocked(), function () {
    return new BlockedException('Usuario está bloqueado');
});
```

#### `throw_unless()`

Lanza la excepción dada a menos que una condición dada evalúe a verdadero.

```php
// Lanzar a menos que condición sea verdadera
throw_unless($user->isAuthorized(), new UnauthorizedException);

// Lanzar a menos que esté autenticado
throw_unless(auth()->check(), new AuthenticationException);

// Lanzar con callback
throw_unless($user->canAccess($resource), function () {
    return new AccessDeniedException('No puede acceder al recurso');
});
```

#### `transform()`

Transforma el valor dado si está presente.

```php
// Transformar si no es null
$result = transform($value, function ($value) {
    return strtoupper($value);
});

// Transformar con valor por defecto
$result = transform($value, function ($value) {
    return strtoupper($value);
}, 'por defecto');

// Transformar null retorna null (a menos que se proporcione valor por defecto)
$result = transform(null, function ($value) {
    return strtoupper($value);
}); // null
```

#### `value()`

Retorna el valor por defecto del valor dado.

```php
// Retornar valor tal como es
$result = value('hola'); // 'hola'

// Ejecutar closure
$result = value(function () {
    return 'valor dinámico';
}); // 'valor dinámico'

// Con parámetros
$result = value(function ($name) {
    return "Hola, {$name}";
}, 'Juan'); // 'Hola, Juan'
```

#### `when()`

Retorna el valor si la condición dada es verdadera.

```php
// Retornar valor si condición es verdadera
$result = when(true, 'valor'); // 'valor'
$result = when(false, 'valor'); // null

// Con callback
$result = when($user->isAdmin(), function () {
    return 'privilegios de admin';
});

// Con valor por defecto
$result = when(false, 'admin', 'invitado'); // 'invitado'
```

#### `with()`

Retorna el valor dado, opcionalmente pasado a través del callback dado.

```php
// Retornar valor tal como es
$result = with('hola'); // 'hola'

// Transformar valor
$result = with('hola', function ($value) {
    return strtoupper($value);
}); // 'HOLA'

// Útil para encadenamiento de métodos
$user = with(new User)->fill($attributes)->save();
```

### Contexto y Defer

#### `context()`

Obtiene o almacena valores de contexto para la petición actual.

```php
// Almacenar contexto
context(['user_id' => auth()->id()]);

// Obtener contexto
$userId = context('user_id');

// Obtener todo el contexto
$allContext = context();

// El contexto se incluye automáticamente en logs
logger('Acción de usuario realizada'); // Incluirá user_id en contexto del log
```

#### `defer()`

Aplaza la ejecución de un callback hasta que la petición esté terminando.

```php
// Aplazar ejecución
defer(function () {
    // Esto se ejecutará después de que se envíe la respuesta
    cleanupTempFiles();
});

// Aplazar con nombre (puede ser cancelado)
defer(function () {
    sendAnalytics();
}, 'analytics');

// Siempre aplazar (incluso si existe defer previo con mismo nombre)
defer(function () {
    logMetrics();
}, 'metrics', always: true);
```

### Testing

#### `fake()`

Obtiene una instancia faker para generar datos falsos en pruebas.

```php
// Generar datos falsos
$name = fake()->name();
$email = fake()->email();
$address = fake()->address();
$text = fake()->text(200);

// Datos falsos específicos de localización
$name = fake('es_ES')->name(); // Nombre en español
$phone = fake('es_ES')->phoneNumber();

// Semilla para datos falsos consistentes
fake()->seed(1234);
$name1 = fake()->name(); // Siempre igual con la misma semilla
```

### Utilidades

#### `laravel_cloud()`

Determina si la aplicación se está ejecutando en Laravel Cloud.

```php
// Verificar si se ejecuta en Laravel Cloud
if (laravel_cloud()) {
    // Ejecutándose en Laravel Cloud
    $cloudConfig = getCloudSpecificConfig();
}

// Lógica condicional para entorno cloud
$cacheDriver = laravel_cloud() ? 'redis' : 'file';
```

#### `precognitive()`

Maneja hook del controlador Precognition.

```php
// En método del controlador
public function store(Request $request)
{
    // Manejar validación precognitiva
    precognitive(function () use ($request) {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users'
        ]);
    });

    // Continuar con procesamiento normal
    $user = User::create($request->validated());

    return response()->json($user);
}
```

#### `preg_replace_array()`

Reemplaza un patrón dado con cada valor en el array en orden secuencial.

```php
$string = 'El :attribute debe ser :type.';
$replacements = ['nombre', 'cadena'];

$result = preg_replace_array('/:attribute|:type/', $replacements, $string);
// Resultado: 'El nombre debe ser cadena.'

// Con patrones más complejos
$string = 'Hola :name, tienes :count mensajes.';
$replacements = ['Juan', '5'];
$result = preg_replace_array('/:name|:count/', $replacements, $string);
// Resultado: 'Hola Juan, tienes 5 mensajes.'
```

#### `windows_os()`

Determina si el SO actual es Windows.

```php
// Verificar si se ejecuta en Windows
if (windows_os()) {
    // Lógica específica de Windows
    $path = str_replace('/', '\\', $path);
}

// Operaciones de archivo condicionales
$separator = windows_os() ? '\\' : '/';
$fullPath = $directory . $separator . $filename;
```

### Vistas

#### `view()`

Obtiene el contenido de vista evaluado para la vista dada.

```php
// Renderizar vista
$html = view('welcome');

// Vista con datos
$html = view('user.profile', ['user' => $user]);

// Vista con array de datos
$html = view('emails.notification', [
    'user' => $user,
    'message' => $message
]);

// Verificar si vista existe
if (view()->exists('custom.template')) {
    $html = view('custom.template');
}

// Retornar respuesta de vista
return view('dashboard', compact('users', 'stats'));
```

---