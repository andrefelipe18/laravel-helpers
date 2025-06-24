# Laravel Helpers - Complete Guide

## Helper Index

| Helper                                            | Description                                          |
| ------------------------------------------------- | ---------------------------------------------------- |
| [`__()`](#__)                                     | Translate message (alias for `trans()`)              |
| [`abort()`](#abort)                               | Throw `HttpException` with given data                |
| [`abort_if()`](#abort-if)                         | Throw `HttpException` if condition is true           |
| [`abort_unless()`](#abort-unless)                 | Throw `HttpException` unless condition is true       |
| [`action()`](#action)                             | Generate URL for controller action                   |
| [`app()`](#app)                                   | Get container instance                               |
| [`app_path()`](#app-path)                         | Get path to application folder                       |
| [`append_config()`](#append-config)               | Append configuration items                           |
| [`asset()`](#asset)                               | Generate asset path                                  |
| [`auth()`](#auth)                                 | Get authentication instance                          |
| [`back()`](#back)                                 | Redirect to previous page                            |
| [`base_path()`](#base-path)                       | Get base path of installation                        |
| [`bcrypt()`](#bcrypt)                             | Hash using `bcrypt` algorithm                        |
| [`blank()`](#blank)                               | Check if value is empty                              |
| [`broadcast()`](#broadcast)                       | Start event broadcast                                |
| [`cache()`](#cache)                               | Manage cache values                                  |
| [`class_basename()`](#class-basename)             | Get base name of class                               |
| [`class_uses_recursive()`](#class-uses-recursive) | Return traits used recursively                       |
| [`collect()`](#collect)                           | Create collection from value                         |
| [`config()`](#config)                             | Manage configuration values                          |
| [`config_path()`](#config-path)                   | Get configuration path                               |
| [`context()`](#context)                           | Manage context for logging                           |
| [`cookie()`](#cookie)                             | Create cookie instance                               |
| [`csrf_field()`](#csrf-field)                     | Generate CSRF form field                             |
| [`csrf_token()`](#csrf-token)                     | Get CSRF token                                       |
| [`data_fill()`](#data-fill)                       | Fill missing data                                    |
| [`data_forget()`](#data-forget)                   | Remove item using dot notation                       |
| [`data_get()`](#data-get)                         | Get item using dot notation                          |
| [`data_set()`](#data-set)                         | Set item using dot notation                          |
| [`database_path()`](#database-path)               | Get database path                                    |
| [`decrypt()`](#decrypt)                           | Decrypt value                                        |
| [`defer()`](#defer)                               | Defer callback execution                             |
| [`dispatch()`](#dispatch)                         | Dispatch job to handler                              |
| [`dispatch_sync()`](#dispatch-sync)               | Dispatch command in current process                  |
| [`e()`](#e)                                       | Encode HTML characters to prevent XSS                |
| [`encrypt()`](#encrypt)                           | Encrypt value                                        |
| [`env()`](#env)                                   | Get environment variable value                       |
| [`event()`](#event)                               | Dispatch event and call listeners                    |
| [`fake()`](#fake)                                 | Get faker instance for testing                       |
| [`filled()`](#filled)                             | Check if value is filled                             |
| [`fluent()`](#fluent)                             | Create Fluent object                                 |
| [`head()`](#head)                                 | Get first element of array                           |
| [`info()`](#info)                                 | Write information to log                             |
| [`lang_path()`](#lang-path)                       | Get language folder path                             |
| [`laravel_cloud()`](#laravel-cloud)               | Check if running on Laravel Cloud                    |
| [`last()`](#last)                                 | Get last element of array                            |
| [`literal()`](#literal)                           | Return literal object using named arguments          |
| [`logger()`](#logger)                             | Log debug message                                    |
| [`logs()`](#logs)                                 | Get log driver instance                              |
| [`method_field()`](#method-field)                 | Generate field to fake HTTP verb                     |
| [`mix()`](#mix)                                   | Get path to versioned Mix file                       |
| [`now()`](#now)                                   | Create Carbon instance for current time              |
| [`object_get()`](#object-get)                     | Get item from object using dot notation              |
| [`old()`](#old)                                   | Retrieve old input item                              |
| [`once()`](#once)                                 | Ensure callable executes only once                   |
| [`optional()`](#optional)                         | Safe access to properties/methods without null error |
| [`policy()`](#policy)                             | Get policy instance                                  |
| [`precognitive()`](#precognitive)                 | Handle Precognition controller hook                  |
| [`preg_replace_array()`](#preg-replace-array)     | Replace pattern with array values                    |
| [`public_path()`](#public-path)                   | Get public folder path                               |
| [`redirect()`](#redirect)                         | Get redirector instance                              |
| [`report()`](#report)                             | Report exception                                     |
| [`report_if()`](#report-if)                       | Report exception if condition is true                |
| [`report_unless()`](#report-unless)               | Report exception unless condition is true            |
| [`request()`](#request)                           | Get current request instance                         |
| [`rescue()`](#rescue)                             | Catch exception and return default value             |
| [`resolve()`](#resolve)                           | Resolve service from container                       |
| [`resource_path()`](#resource-path)               | Get resources folder path                            |
| [`response()`](#response)                         | Return new application response                      |
| [`retry()`](#retry)                               | Try to execute operation multiple times              |
| [`route()`](#route)                               | Generate URL for named route                         |
| [`secure_asset()`](#secure-asset)                 | Generate asset path with HTTPS                       |
| [`secure_url()`](#secure-url)                     | Generate HTTPS URL                                   |
| [`session()`](#session)                           | Manage session values                                |
| [`storage_path()`](#storage-path)                 | Get storage folder path                              |
| [`str()`](#str)                                   | Get stringable object                                |
| [`tap()`](#tap)                                   | Call Closure with value and return value             |
| [`throw_if()`](#throw-if)                         | Throw exception if condition is true                 |
| [`throw_unless()`](#throw-unless)                 | Throw exception unless condition is true             |
| [`to_route()`](#to-route)                         | Create redirect to named route                       |
| [`today()`](#today)                               | Create Carbon instance for current date              |
| [`trait_uses_recursive()`](#trait-uses-recursive) | Return traits used by a trait                        |
| [`trans()`](#trans)                               | Translate message                                    |
| [`trans_choice()`](#trans-choice)                 | Translate message based on count                     |
| [`transform()`](#transform)                       | Transform value if present                           |
| [`url()`](#url)                                   | Generate URL for application                         |
| [`validator()`](#validator)                       | Create Validator instance                            |
| [`value()`](#value)                               | Return default value (resolve Closures)              |
| [`view()`](#view)                                 | Get evaluated view content                           |
| [`when()`](#when)                                 | Return value if condition is true                    |
| [`windows_os()`](#windows-os)                     | Check if environment is Windows-based                |
| [`with()`](#with)                                 | Return value passed through callback                 |

---

## Helpers by Category

### Assets and Mix

#### `fake()`

Get a faker instance for testing and generating fake data.

```php
// Generate fake name
$name = fake()->name();

// Generate fake email
$email = fake()->email();

// Generate fake text
$text = fake()->text(200);
```

#### `mix()`

Get the path to a versioned Laravel Mix file, including version hash for cache busting.

```php
// Path to versioned CSS file
echo mix('css/app.css'); // /css/app.css?id=abc123

// Path to versioned JS file
echo mix('js/app.js'); // /js/app.js?id=def456
```

### Authentication and Authorization

#### `auth()`

Get the available authentication instance or a specific guard.

```php
// Get authenticated user
$user = auth()->user();

// Check if authenticated
if (auth()->check()) {
    // User is logged in
}

// Use specific guard
$admin = auth('admin')->user();
```

#### `policy()`

Get a policy instance for authorization.

```php
// Get user policy
$policy = policy(User::class);

// Check permission
if ($policy->view($user, $post)) {
    // User can view post
}
```

### URL Generation

#### `action()`

Generate a URL for a controller action.

```php
// URL for controller action
$url = action([UserController::class, 'show'], ['id' => 1]);
// /user/1

// URL with additional parameters
$url = action([UserController::class, 'edit'], ['user' => 1], false);
// user/1/edit (relative URL)
```

#### `asset()`

Generate a URL for an application asset.

```php
// Asset URL
echo asset('css/app.css'); // /css/app.css

// Asset with subdomain
echo asset('images/logo.png'); // /images/logo.png
```

#### `route()`

Generate a URL for a named route.

```php
// Named route URL
$url = route('user.show', ['id' => 1]);

// Route with parameters
$url = route('user.edit', ['user' => $user]);

// Absolute URL
$url = route('user.show', ['id' => 1], true);
```

#### `secure_asset()`

Generate a URL for an application asset using HTTPS.

```php
// Secure asset URL
echo secure_asset('css/app.css'); // https://example.com/css/app.css
```

#### `secure_url()`

Generate a fully qualified HTTPS URL for the application.

```php
// Secure URL
echo secure_url('user/profile'); // https://example.com/user/profile

// Secure URL with parameters
echo secure_url('user/profile', ['tab' => 'settings']);
```

#### `url()`

Generate a fully qualified URL for the application.

```php
// Generate URL
echo url('user/profile'); // http://example.com/user/profile

// URL with parameters
echo url('user/profile', ['tab' => 'settings']);
// http://example.com/user/profile?tab=settings

// Secure URL
echo url('user/profile', [], true); // https://example.com/user/profile
```

### Response and Redirect

#### `abort()`

Throw an HTTP exception.

```php
// 404 error
abort(404);

// 403 error with message
abort(403, 'Unauthorized action.');

// 500 error with headers
abort(500, 'Server Error', ['X-Custom-Header' => 'value']);
```

#### `abort_if()`

Throw an HTTP exception if a condition is true.

```php
// Abort if user is not admin
abort_if(!auth()->user()->isAdmin(), 403);

// Abort with custom message
abort_if($errors->any(), 422, 'Validation failed');
```

#### `abort_unless()`

Throw an HTTP exception unless a condition is true.

```php
// Abort unless user owns the post
abort_unless($user->owns($post), 403);

// Abort unless authenticated
abort_unless(auth()->check(), 401, 'Authentication required');
```

#### `back()`

Create a redirect response to the user's previous location.

```php
// Redirect back
return back();

// Redirect back with data
return back()->with('success', 'Profile updated!');

// Redirect back with input
return back()->withInput();

// Redirect back with errors
return back()->withErrors(['email' => 'Invalid email']);
```

#### `redirect()`

Get an instance of the redirector.

```php
// Simple redirect
return redirect('/home');

// Redirect to named route
return redirect()->route('user.show', ['id' => 1]);

// Redirect to controller action
return redirect()->action([UserController::class, 'index']);

// Redirect with data
return redirect('/home')->with('success', 'Welcome!');
```

#### `response()`

Return a new response from the application.

```php
// Simple response
return response('Hello World');

// JSON response
return response()->json(['message' => 'Success']);

// Response with status and headers
return response('Not Found', 404, ['Content-Type' => 'text/plain']);

// Download response
return response()->download('/path/to/file.pdf');
```

#### `to_route()`

Create a redirect response to a named route.

```php
// Redirect to named route
return to_route('user.show', ['id' => 1]);

// Redirect with status code
return to_route('user.index', [], 302);
```

### Application Paths

#### `app_path()`

Get the path to the application folder.

```php
// App directory path
$path = app_path(); // /path/to/app

// Path to specific file
$path = app_path('Http/Controllers/UserController.php');
// /path/to/app/Http/Controllers/UserController.php
```

#### `base_path()`

Get the path to the project root.

```php
// Base path
$path = base_path(); // /path/to/project

// Path to specific file
$path = base_path('composer.json'); // /path/to/project/composer.json
```

#### `config_path()`

Get the path to the configuration folder.

```php
// Config directory path
$path = config_path(); // /path/to/config

// Path to specific config file
$path = config_path('app.php'); // /path/to/config/app.php
```

#### `database_path()`

Get the path to the database folder.

```php
// Database directory path
$path = database_path(); // /path/to/database

// Path to specific file
$path = database_path('migrations'); // /path/to/database/migrations
```

#### `lang_path()`

Get the path to the language folder.

```php
// Language directory path
$path = lang_path(); // /path/to/lang

// Path to specific language file
$path = lang_path('en/messages.php'); // /path/to/lang/en/messages.php
```

#### `public_path()`

Get the path to the public folder.

```php
// Public directory path
$path = public_path(); // /path/to/public

// Path to specific file
$path = public_path('css/app.css'); // /path/to/public/css/app.css
```

#### `resource_path()`

Get the path to the resources folder.

```php
// Resources directory path
$path = resource_path(); // /path/to/resources

// Path to specific file
$path = resource_path('views/welcome.blade.php');
// /path/to/resources/views/welcome.blade.php
```

#### `storage_path()`

Get the path to the storage folder.

```php
// Storage directory path
$path = storage_path(); // /path/to/storage

// Path to specific file
$path = storage_path('app/file.txt'); // /path/to/storage/app/file.txt
```

### Container and Services

#### `app()`

Get the available container instance or resolve a service.

```php
// Get application instance
$app = app();

// Resolve service from container
$cache = app('cache');

// Resolve with parameters
$service = app(UserService::class, ['param' => 'value']);
```

#### `resolve()`

Resolve a service from the container.

```php
// Resolve service
$cache = resolve('cache');

// Resolve class
$service = resolve(UserService::class);
```

### Configuration

#### `config()`

Get or set configuration values.

```php
// Get configuration value
$timezone = config('app.timezone');

// Get with default value
$debug = config('app.debug', false);

// Set configuration value
config(['app.locale' => 'en']);

// Set multiple values
config([
    'app.timezone' => 'UTC',
    'app.locale' => 'en'
]);
```

#### `append_config()`

Append configuration items to an array configuration value.

```php
// Append to array config
append_config(['app.providers' => [
    CustomServiceProvider::class
]]);
```

#### `env()`

Get the value of an environment variable.

```php
// Get environment variable
$debug = env('APP_DEBUG');

// Get with default value
$debug = env('APP_DEBUG', false);

// Environment variable with type casting
$timeout = env('SESSION_LIFETIME', 120);
```

### Caching

#### `cache()`

Get or store values in the cache.

```php
// Get cache value
$value = cache('key');

// Get with default
$value = cache('key', 'default');

// Store in cache
cache(['key' => 'value'], now()->addHour());

// Store with tags
cache()->tags(['users', 'posts'])->put('key', 'value', 3600);
```

### Session

#### `session()`

Get or store session values.

```php
// Get session value
$value = session('key');

// Get with default
$value = session('key', 'default');

// Store in session
session(['key' => 'value']);

// Flash data to session
session()->flash('message', 'Success!');
```

#### `old()`

Retrieve a flashed input value from the session.

```php
// Get old input
$email = old('email');

// Get with default
$name = old('name', 'John Doe');

// In Blade template
<input type="email" name="email" value="{{ old('email') }}">
```

### Cookies

#### `cookie()`

Create a new cookie instance.

```php
// Create cookie
$cookie = cookie('name', 'value', 60);

// Cookie with domain and secure
$cookie = cookie('name', 'value', 60, '/', '.domain.com', true, true);

// Queue cookie for next response
cookie()->queue('name', 'value', 60);
```

### CSRF Protection

#### `csrf_field()`

Generate an HTML hidden input field containing the CSRF token.

```php
// In Blade template
{{ csrf_field() }}

// Outputs: <input type="hidden" name="_token" value="...">
```

#### `csrf_token()`

Get the CSRF token value.

```php
// Get CSRF token
$token = csrf_token();

// In JavaScript
const token = '{{ csrf_token() }}';
```

#### `method_field()`

Generate an HTML hidden input field containing the HTTP verb.

```php
// In Blade template for PUT request
{{ method_field('PUT') }}

// Outputs: <input type="hidden" name="_method" value="PUT">

// For DELETE request
{{ method_field('DELETE') }}
```

### Request and Input

#### `request()`

Get the current request instance or an input value.

```php
// Get request instance
$request = request();

// Get input value
$email = request('email');

// Get with default
$name = request('name', 'Guest');

// Get all input
$input = request()->all();
```

### Validation

#### `validator()`

Create a validator instance.

```php
// Create validator
$validator = validator(['email' => 'test@example.com'], [
    'email' => 'required|email'
]);

// Check if validation passes
if ($validator->passes()) {
    // Validation passed
}

// Get validation errors
$errors = $validator->errors();
```

### Date and Time

#### `now()`

Create a Carbon instance for the current date and time.

```php
// Current timestamp
$now = now();

// Current timestamp in specific timezone
$now = now('America/New_York');

// Format current time
echo now()->format('Y-m-d H:i:s');

// Add time
$future = now()->addHours(2);
```

#### `today()`

Create a Carbon instance for the current date.

```php
// Today's date
$today = today();

// Today in specific timezone
$today = today('America/New_York');

// Format today's date
echo today()->format('Y-m-d');

// Start of day
$startOfDay = today()->startOfDay();
```

### Localization

#### `__()`

Translate the given message (alias for `trans()`).

```php
// Simple translation
echo __('Welcome');

// Translation with parameters
echo __('Welcome, :name', ['name' => 'John']);

// Translation from specific file
echo __('messages.welcome');

// Translation with fallback
echo __('messages.welcome', [], 'en');
```

#### `trans()`

Translate the given message.

```php
// Simple translation
echo trans('Welcome');

// Translation with parameters
echo trans('Welcome, :name', ['name' => 'John']);

// Translation from specific file
echo trans('messages.welcome');
```

#### `trans_choice()`

Translate the given message based on a count.

```php
// Pluralization
echo trans_choice('messages.notifications', $count);

// With parameters
echo trans_choice('messages.notifications', $count, ['name' => 'John']);

// Manual count specification
echo trans_choice('messages.items', 5, ['count' => 5]);
```

### Logging

#### `info()`

Write an informational message to the logs.

```php
// Simple info log
info('User logged in');

// Info with context
info('User logged in', ['user_id' => 123]);

// Info with additional data
info('Processing payment', [
    'amount' => 100,
    'currency' => 'USD',
    'user_id' => 123
]);
```

#### `logger()`

Log a debug message to the logs or get a logger instance.

```php
// Log debug message
logger('Debug information');

// Log with context
logger('User action', ['action' => 'login', 'user_id' => 123]);

// Get logger instance
$logger = logger();
$logger->error('Error message');
```

#### `logs()`

Get a log driver instance.

```php
// Get default log driver
$log = logs();

// Get specific driver
$slackLog = logs('slack');

// Log with specific driver
logs('slack')->info('Important notification');
```

#### `report()`

Report an exception to the exception handler.

```php
// Report exception
try {
    // Some code that might fail
} catch (Exception $e) {
    report($e);
}

// Report with context
report($exception, ['user_id' => auth()->id()]);
```

#### `report_if()`

Report an exception if a given condition is true.

```php
// Report exception if condition is true
report_if($shouldReport, $exception);

// Report with context
report_if(app()->isProduction(), $exception, ['context' => 'production']);
```

#### `report_unless()`

Report an exception unless a given condition is true.

```php
// Report exception unless condition is true
report_unless($shouldIgnore, $exception);

// Report unless in testing
report_unless(app()->runningUnitTests(), $exception);
```

### Events and Broadcasting

#### `broadcast()`

Begin broadcasting an event.

```php
// Broadcast event
broadcast(new OrderUpdated($order));

// Broadcast to specific channels
broadcast(new OrderUpdated($order))->to(['order.' . $order->id]);

// Broadcast with delay
broadcast(new OrderUpdated($order))->delay(now()->addMinutes(5));
```

#### `event()`

Dispatch an event and call its listeners.

```php
// Dispatch event
event(new UserRegistered($user));

// Dispatch with multiple parameters
event('user.login', [$user, $request]);

// Dispatch until first non-null response
$response = event('user.login', [$user], true);
```

### Queues and Jobs

#### `dispatch()`

Dispatch a job to its appropriate handler.

```php
// Dispatch job
dispatch(new ProcessPayment($order));

// Dispatch with delay
dispatch(new ProcessPayment($order))->delay(now()->addMinutes(10));

// Dispatch to specific queue
dispatch(new ProcessPayment($order))->onQueue('payments');

// Dispatch to specific connection
dispatch(new ProcessPayment($order))->onConnection('redis');
```

#### `dispatch_sync()`

Dispatch a command to its appropriate handler in the current process.

```php
// Dispatch synchronously
dispatch_sync(new ProcessPayment($order));

// Useful for testing or immediate execution
dispatch_sync(new SendWelcomeEmail($user));
```

### Security

#### `bcrypt()`

Hash the given value using the bcrypt algorithm.

```php
// Hash password
$hash = bcrypt('password');

// Hash with custom rounds
$hash = bcrypt('password', ['rounds' => 12]);

// Verify password
if (password_verify('password', $hash)) {
    // Password is correct
}
```

#### `decrypt()`

Decrypt the given value.

```php
// Decrypt value
$decrypted = decrypt($encryptedValue);

// Decrypt with specific cipher
$decrypted = decrypt($encryptedValue, false);
```

#### `encrypt()`

Encrypt the given value.

```php
// Encrypt value
$encrypted = encrypt('secret data');

// Encrypt for serialization
$encrypted = encrypt($object, true);
```

#### `e()`

Encode HTML characters in a string to prevent XSS attacks.

```php
// Escape HTML
echo e('<script>alert("XSS")</script>');
// Output: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;

// Escape user input
echo e($userInput);

// In Blade templates (automatic escaping)
{{ $userInput }} // Automatically escaped
{!! $trustedInput !!} // Not escaped
```

### Data Manipulation

#### `blank()`

Determine if the given value is "blank".

```php
// Check if blank
blank(''); // true
blank(null); // true
blank([]); // true
blank(collect()); // true
blank('   '); // true
blank('hello'); // false
```

#### `filled()`

Determine if the given value is not "blank".

```php
// Check if filled
filled('hello'); // true
filled([1, 2, 3]); // true
filled(''); // false
filled(null); // false
filled([]); // false
```

#### `collect()`

Create a collection from the given value.

```php
// Create collection from array
$collection = collect([1, 2, 3]);

// Create empty collection
$empty = collect();

// Collection methods
$collection->filter(function ($item) {
    return $item > 1;
})->map(function ($item) {
    return $item * 2;
});
```

#### `data_fill()`

Fill in missing values in an array or object using dot notation.

```php
$data = ['products' => ['desk' => ['price' => 100]]];

// Fill missing values
data_fill($data, 'products.desk.name', 'Desk');
data_fill($data, 'products.chair.price', 200);

// Result: ['products' => ['desk' => ['price' => 100, 'name' => 'Desk'], 'chair' => ['price' => 200]]]
```

#### `data_forget()`

Remove an item from an array or object using dot notation.

```php
$data = [
    'products' => [
        'desk' => ['price' => 100, 'name' => 'Desk'],
        'chair' => ['price' => 200]
    ]
];

// Remove item
data_forget($data, 'products.desk.name');
data_forget($data, 'products.chair');
```

#### `data_get()`

Retrieve an item from an array or object using dot notation.

```php
$data = [
    'products' => [
        'desk' => ['price' => 100, 'name' => 'Desk']
    ]
];

// Get item
$price = data_get($data, 'products.desk.price'); // 100
$name = data_get($data, 'products.desk.name'); // 'Desk'

// Get with default
$color = data_get($data, 'products.desk.color', 'brown'); // 'brown'

// Use wildcard
$prices = data_get($data, 'products.*.price'); // [100]
```

#### `data_set()`

Set an item on an array or object using dot notation.

```php
$data = ['products' => ['desk' => ['price' => 100]]];

// Set item
data_set($data, 'products.desk.name', 'Desk');
data_set($data, 'products.chair.price', 200);

// Set with wildcard
data_set($data, 'products.*.discount', 10);
```

#### `head()`

Return the first element in an array.

```php
// Get first element
$first = head([1, 2, 3]); // 1
$first = head(['a' => 1, 'b' => 2]); // 1

// Empty array
$first = head([]); // null
```

#### `last()`

Return the last element in an array.

```php
// Get last element
$last = last([1, 2, 3]); // 3
$last = last(['a' => 1, 'b' => 2]); // 2

// Empty array
$last = last([]); // null
```

### String and Object Manipulation

#### `class_basename()`

Get the class "basename" of the given object / class.

```php
// Get class basename
$basename = class_basename('App\Http\Controllers\UserController'); // 'UserController'
$basename = class_basename(new User); // 'User'
$basename = class_basename(User::class); // 'User'
```

#### `class_uses_recursive()`

Return all of the trait names used by a class, its parent classes, and trait dependencies.

```php
// Get all traits used by class
$traits = class_uses_recursive(User::class);

// Example output: ['Illuminate\Database\Eloquent\Concerns\HasTimestamps', ...]
```

#### `trait_uses_recursive()`

Return all of the trait names used by a trait and its dependencies.

```php
// Get traits used by a trait
$traits = trait_uses_recursive(SomeTraitName::class);
```

#### `fluent()`

Create a fluent object from the given value.

```php
// Create fluent object
$fluent = fluent(['name' => 'John', 'age' => 30]);

// Access properties
echo $fluent->name; // 'John'
echo $fluent->get('age'); // 30

// Set properties
$fluent->email = 'john@example.com';
$fluent->set('phone', '123-456-7890');
```

#### `literal()`

Return a new object with the given named arguments.

```php
// Create object with named arguments
$object = literal(name: 'John', age: 30, city: 'New York');

// Access properties
echo $object->name; // 'John'
echo $object->age; // 30
```

#### `object_get()`

Retrieve an item from an object using dot notation.

```php
$object = (object) [
    'user' => (object) [
        'name' => 'John',
        'email' => 'john@example.com'
    ]
];

// Get property
$name = object_get($object, 'user.name'); // 'John'
$email = object_get($object, 'user.email'); // 'john@example.com'

// Get with default
$phone = object_get($object, 'user.phone', 'N/A'); // 'N/A'
```

#### `str()`

Get a new stringable object from the given string.

```php
// Create stringable object
$str = str('Hello World');

// String manipulation
$result = str('hello world')
    ->title()
    ->replace('World', 'Laravel')
    ->slug();

// Method chaining
$slug = str('Hello World')->slug(); // 'hello-world'
$title = str('hello world')->title(); // 'Hello World'
```

### Control Flow

#### `once()`

Ensure that a callable is executed only once.

```php
$expensive = once(function () {
    // This expensive operation will only run once
    return expensiveOperation();
});

// First call executes the function
$result1 = $expensive(); // Executes expensiveOperation()

// Subsequent calls return cached result
$result2 = $expensive(); // Returns cached result
```

#### `optional()`

Return the value if it exists or a default value.

```php
// Safe property access
$name = optional($user)->name;

// Safe method calls
$email = optional($user)->getEmail();

// Chained calls
$phone = optional($user)->profile->phone;

// With callback
$result = optional($user, function ($user) {
    return $user->name . ' - ' . $user->email;
});
```

#### `rescue()`

Execute the given callback and catch any exceptions that occur during execution.

```php
// Rescue with default value
$result = rescue(function () {
    return riskyOperation();
}, 'default value');

// Rescue with callback for exception handling
$result = rescue(function () {
    return riskyOperation();
}, function ($exception) {
    report($exception);
    return 'fallback value';
});

// Simple rescue
$result = rescue(fn() => $user->profile->phone, 'N/A');
```

#### `retry()`

Attempt to execute the given callback until the given maximum attempt threshold is met.

```php
// Retry up to 3 times
$result = retry(3, function () {
    // Potentially failing operation
    return callExternalAPI();
});

// Retry with delay (milliseconds)
$result = retry(3, function () {
    return callExternalAPI();
}, 1000);

// Retry with custom delay function
$result = retry(3, function () {
    return callExternalAPI();
}, function ($attempt) {
    return $attempt * 1000; // Exponential backoff
});

// Retry with when condition
$result = retry(3, function () {
    return callExternalAPI();
}, 1000, function ($exception) {
    return $exception instanceof ConnectionException;
});
```

#### `tap()`

Call the given closure with the given value then return the value.

```php
// Tap into value
$user = tap(new User, function ($user) {
    $user->name = 'John';
    $user->email = 'john@example.com';
});

// Tap with method calls
$collection = tap(collect([1, 2, 3]), function ($collection) {
    $collection->push(4);
});

// Tap for debugging
$result = tap($someValue, function ($value) {
    logger('Processing value: ' . $value);
});
```

#### `throw_if()`

Throw the given exception if a given condition evaluates to true.

```php
// Throw if condition is true
throw_if($user->isNotAuthorized(), new UnauthorizedException);

// Throw with message
throw_if($errors->any(), ValidationException::class, 'Validation failed');

// Throw with callback
throw_if($user->isBlocked(), function () {
    return new BlockedException('User is blocked');
});
```

#### `throw_unless()`

Throw the given exception unless a given condition evaluates to true.

```php
// Throw unless condition is true
throw_unless($user->isAuthorized(), new UnauthorizedException);

// Throw unless authenticated
throw_unless(auth()->check(), new AuthenticationException);

// Throw with callback
throw_unless($user->canAccess($resource), function () {
    return new AccessDeniedException('Cannot access resource');
});
```

#### `transform()`

Transform the given value if it is present.

```php
// Transform if not null
$result = transform($value, function ($value) {
    return strtoupper($value);
});

// Transform with default
$result = transform($value, function ($value) {
    return strtoupper($value);
}, 'default');

// Transform null returns null (unless default provided)
$result = transform(null, function ($value) {
    return strtoupper($value);
}); // null
```

#### `value()`

Return the default value of the given value.

```php
// Return value as-is
$result = value('hello'); // 'hello'

// Execute closure
$result = value(function () {
    return 'dynamic value';
}); // 'dynamic value'

// With parameters
$result = value(function ($name) {
    return "Hello, {$name}";
}, 'John'); // 'Hello, John'
```

#### `when()`

Return the value if the given condition is true.

```php
// Return value if condition is true
$result = when(true, 'value'); // 'value'
$result = when(false, 'value'); // null

// With callback
$result = when($user->isAdmin(), function () {
    return 'admin privileges';
});

// With default value
$result = when(false, 'admin', 'guest'); // 'guest'
```

#### `with()`

Return the given value, optionally passed through the given callback.

```php
// Return value as-is
$result = with('hello'); // 'hello'

// Transform value
$result = with('hello', function ($value) {
    return strtoupper($value);
}); // 'HELLO'

// Useful for method chaining
$user = with(new User)->fill($attributes)->save();
```

### Context and Defer

#### `context()`

Get or store context values for the current request.

```php
// Store context
context(['user_id' => auth()->id()]);

// Get context
$userId = context('user_id');

// Get all context
$allContext = context();

// Context is automatically included in logs
logger('User action performed'); // Will include user_id in log context
```

#### `defer()`

Defer the execution of a callback until the request is terminating.

```php
// Defer execution
defer(function () {
    // This will run after the response is sent
    cleanupTempFiles();
});

// Defer with name (can be cancelled)
defer(function () {
    sendAnalytics();
}, 'analytics');

// Always defer (even if previous defer with same name exists)
defer(function () {
    logMetrics();
}, 'metrics', always: true);
```

### Testing

#### `fake()`

Get a faker instance for generating fake data in tests.

```php
// Generate fake data
$name = fake()->name();
$email = fake()->email();
$address = fake()->address();
$text = fake()->text(200);

// Locale-specific fake data
$name = fake('pt_BR')->name(); // Brazilian Portuguese name
$phone = fake('pt_BR')->phoneNumber();

// Seed for consistent fake data
fake()->seed(1234);
$name1 = fake()->name(); // Always same with same seed
```

### Utilities

#### `laravel_cloud()`

Determine if the application is running on Laravel Cloud.

```php
// Check if running on Laravel Cloud
if (laravel_cloud()) {
    // Running on Laravel Cloud
    $cloudConfig = getCloudSpecificConfig();
}

// Conditional logic for cloud environment
$cacheDriver = laravel_cloud() ? 'redis' : 'file';
```

#### `precognitive()`

Handle Precognition controller hook.

```php
// In controller method
public function store(Request $request)
{
    // Handle precognitive validation
    precognitive(function () use ($request) {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users'
        ]);
    });

    // Continue with normal processing
    $user = User::create($request->validated());

    return response()->json($user);
}
```

#### `preg_replace_array()`

Replace a given pattern with each value in the array in a sequential order.

```php
$string = 'The :attribute must be :type.';
$replacements = ['name', 'string'];

$result = preg_replace_array('/:attribute|:type/', $replacements, $string);
// Result: 'The name must be string.'

// With more complex patterns
$string = 'Hello :name, you have :count messages.';
$replacements = ['John', '5'];
$result = preg_replace_array('/:name|:count/', $replacements, $string);
// Result: 'Hello John, you have 5 messages.'
```

#### `windows_os()`

Determine if the current OS is Windows.

```php
// Check if running on Windows
if (windows_os()) {
    // Windows-specific logic
    $path = str_replace('/', '\\', $path);
}

// Conditional file operations
$separator = windows_os() ? '\\' : '/';
$fullPath = $directory . $separator . $filename;
```

### Views

#### `view()`

Get the evaluated view contents for the given view.

```php
// Render view
$html = view('welcome');

// View with data
$html = view('user.profile', ['user' => $user]);

// View with data array
$html = view('emails.notification', [
    'user' => $user,
    'message' => $message
]);

// Check if view exists
if (view()->exists('custom.template')) {
    $html = view('custom.template');
}

// Return view response
return view('dashboard', compact('users', 'stats'));
```

---
