package org.jscep.transport;


/**
 * Simplifies exception mapping from one layer to another
 *
 * @param <T> type of result
 */
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