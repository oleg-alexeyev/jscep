package org.jscep.transport;


public abstract class ErrorDelegatingHandler<T>
        implements ResultHandler<T> {

    private final ResultHandler<?> errorHandler;

    public ErrorDelegatingHandler(ResultHandler<?> errorHandler) {
        this.errorHandler = errorHandler;
    }

    @Override
    public void handle(T t, Throwable e) {
        if (e == null) {
            doHandle(t);
        } else {
            errorHandler.handle(null, e);
        }
    }

    protected abstract void doHandle(T t);
}