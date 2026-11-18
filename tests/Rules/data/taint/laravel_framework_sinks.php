<?php

declare(strict_types=1);

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Storage;
use Illuminate\View\Compilers\BladeCompiler;

function cases(Request $request, BladeCompiler $blade, PendingProcess $process, Filesystem $disk, UploadedFile $file): void
{
    Blade::render($request->input('t')); // unsafe
    Blade::compileString($request->input('t')); // unsafe
    BladeCompiler::render($request->input('t')); // unsafe
    $blade->compileString($request->input('t')); // unsafe

    Process::run('ls ' . $request->input('d')); // unsafe
    Process::start('ls ' . $request->input('d')); // unsafe
    Process::command('ls ' . $request->input('d')); // unsafe
    $process->run('ls ' . $request->input('d')); // unsafe
    $process->start('ls ' . $request->input('d')); // unsafe
    $process->command('ls ' . $request->input('d')); // unsafe

    redirect($request->input('next')); // unsafe
    redirect()->to($request->input('next')); // unsafe
    redirect()->away($request->input('next')); // unsafe
    Redirect::to($request->input('next')); // unsafe
    Redirect::away($request->input('next')); // unsafe

    Storage::get($request->input('path')); // unsafe
    Storage::put($request->input('path'), 'x'); // unsafe
    Storage::putFileAs($request->input('path'), $file); // unsafe
    Storage::putFileAs('uploads', $file, $request->input('name')); // unsafe
    Storage::delete($request->input('path')); // unsafe
    $disk->get($request->input('path')); // unsafe
    $disk->put($request->input('path'), 'x'); // unsafe
    $disk->putFileAs('uploads', $file, $request->input('name')); // unsafe
    $disk->delete($request->input('path')); // unsafe

    $file->store($request->input('dir')); // unsafe
    $file->storePublicly($request->input('dir')); // unsafe
    $file->storeAs($request->input('dir'), 'avatar.png'); // unsafe
    $file->storeAs('uploads', $request->input('name')); // unsafe
    $file->storePubliclyAs('uploads', $request->input('name')); // unsafe

    response($request->input('html')); // unsafe
}

function safe(Request $request, PendingProcess $process, Filesystem $disk, UploadedFile $file): void
{
    Blade::render('Hello {{ $name }}', ['name' => $request->input('name')]); // safe (view data is not compiled, and {{ }} escapes it)

    Process::run(['ls', $request->input('d')]); // safe (an array command bypasses the shell)
    $process->run(['ls', $request->input('d')]); // safe (an array command bypasses the shell)

    redirect()->route('profile', ['id' => $request->input('id')]); // safe (named routes build the URL)
    Redirect::to('/dashboard', $request->input('status')); // safe (only the target is a sink)

    Storage::put('notes/latest.txt', $request->input('body')); // safe (only the path is a sink)
    $disk->put('notes/latest.txt', $request->input('body')); // safe (only the path is a sink)
    $file->store('uploads'); // safe (literal directory, generated file name)
    $file->storeAs('uploads', $file->hashName()); // safe (generated file name)

    response('Saved', $request->input('status')); // safe (only the content is a sink)
    response()->json($request->input('data')); // safe (JSON, not HTML)
}
