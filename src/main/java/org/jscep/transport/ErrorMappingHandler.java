package org.jscep.transport;


/**
 * Simplifies result handling by delegating error handling to another handler.
 *
 * @param <T> type of result
 */
public abstract class ErrorMappingHandler<T> implements ResultHandler<T> {

    private final ResultHandler<T> handler;

    public ErrorMappingHandler(ResultHandler<T> handler) {
        this.handler = handler;
    }

    @Override
    public void handle(T t, Throwable e) {
        Throwable error = e != null ? mapError(e) : null;
        handler.handle(t, error);
    }

    protected abstract Throwable mapError(Throwable e);
}