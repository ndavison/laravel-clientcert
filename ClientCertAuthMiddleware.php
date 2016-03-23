<?php

namespace App\Http\Middleware;

use Auth;
use Closure;
use Request;
use App\User;
use phpseclib\File\X509;

class ClientCertAuthMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if (!Request::secure()) {
            return response()->view('errors.400', ['error' => 'The Client Certificate middleware requires a HTTPS connection.'], 400);
        }

        // the DN from the client certificate contains the CN, which forms the username
        $dn = Request::server('SSL_CLIENT_S_DN');
        preg_match('/cn=([^,\/]+)/i', $dn, $matches);
        $cn = isset($matches[1]) ? $matches[1] : null;

        if (!$cn) {
            return response()->view('errors.400', ['error' => 'Failed to get the certificate CN - did you provide a certificate in the request?'], 400);
        }

        // check if the user exists, if not, create it
        $user = User::where('name', $cn)->first();
        if (!$user) {
            $user = User::create(['name' => $cn]);
        }

        // authenticate the user
        Auth::login($user);

        // authenticate the user
        return $next($request);
    }
}
