<?php

namespace Lab404\Impersonate\Services;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Lab404\Impersonate\Events\LeaveImpersonation;
use Lab404\Impersonate\Events\TakeImpersonation;
use Illuminate\Contracts\Auth\Authenticatable;

class ImpersonateManager
{
    /**
     * @var Application
     */
    private $app;

    /**
     * UserFinder constructor.
     *
     * @param Application $app
     */
    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * @param   int $id
     * @return  Model
     */
    public function findUserById($id, $model = null)
    {
        $model = $model ?? $this->app['config']->get('auth.providers.users.model');

        $user = call_user_func([
            $model,
            'findOrFail'
        ], $id);

        return $user;
    }

    /**
     * @return bool
     */
    public function isImpersonating()
    {
        return session()->has($this->getSessionKey());
    }

    /**
     * @param   void
     * @return  int|null
     */
    public function getImpersonatorId()
    {
        return session($this->getSessionKey(), null);
    }

    /**
     * @param Model $from
     * @param Model $to
     * @return bool
     */
    public function take($from, $to)
    {
        try {
            $fromGuard = $this->determineGuard($from);
            $toGuard   = $this->determineGuard($to);

            session()->put(config('laravel-impersonate.session_key'), [
                'key'   => $from->getKey(),
                'from'  => $fromGuard,
                'to'    => $toGuard,
            ]);

            $this->app['auth']->guard($fromGuard)->quietLogout();
            $this->app['auth']->guard($toGuard)->quietLogin($to);

        } catch (\Exception $e) {
            unset($e);
            return false;
        }

        $this->app['events']->fire(new TakeImpersonation($from, $to));

        return true;
    }

    /**
     * @return  bool
     */
    public function leave()
    {
        try {
            $imp = $this->getImpersonatorId();
            $fromGuard = $imp['to'];
            $toGuard   = $imp['from'];

            $provider = config("auth.guards.{$toGuard}.provider");
            $model = config("auth.providers.{$provider}.model");

            $impersonated = $this->app['auth']->guard($fromGuard)->user();
            $impersonator = $this->findUserById($imp['key'], $model);

            $this->app['auth']->guard($fromGuard)->quietLogout();
            $this->app['auth']->guard($toGuard)->quietLogin($impersonator);

            $this->clear();

        } catch (\Exception $e) {
            unset($e);
            return false;
        }

        $this->app['events']->fire(new LeaveImpersonation($impersonator, $impersonated));

        return true;
    }

    /**
     * @return void
     */
    public function clear()
    {
        session()->forget($this->getSessionKey());
    }

    /**
     * @return string
     */
    public function getSessionKey()
    {
        return config('laravel-impersonate.session_key');
    }

    /**
     * @return  string
     */
    public function getTakeRedirectTo()
    {
        try {
            $uri = route(config('laravel-impersonate.take_redirect_to'));
        } catch (\InvalidArgumentException $e) {
            $uri = config('laravel-impersonate.take_redirect_to');
        }

        return $uri;
    }

    /**
     * @return  string
     */
    public function getLeaveRedirectTo()
    {
        try {
            $uri = route(config('laravel-impersonate.leave_redirect_to'));
        } catch (\InvalidArgumentException $e) {
            $uri = config('laravel-impersonate.leave_redirect_to');
        }

        return $uri;
    }

    /**
     * @return  string
     */
    public function determineGuard(Authenticatable $user)
    {
        $class     = get_class($user);
        $guards    = config('auth.guards');
        $providers = config('auth.providers');

        $provider = array_reduce(array_keys($providers), function($result, $key) use ($class, $providers) {
            if($providers[$key]['model'] == $class && $providers[$key]['driver'] == 'eloquent') {
                $result = $key;
            }
            return $result;
        }, '');

        if(empty($provider)) {
            throw new \Exception("Error when selecting provider for {$class}");
        }

        $guard = array_reduce(array_keys($guards), function($result, $key) use ($provider, $guards) {
            if($guards[$key]['provider'] == $provider && $guards[$key]['driver'] == 'session') {
                $result = $key;
            }
            return $result;
        }, '');

        if(empty($guard)) {
            throw new \Exception("Error when selecting guard for {$provider} provider.");
        }

        return $guard;
    }
}
