package org.jscep.transport;


public final class ResultHolder<T, E extends Throwable>
        implements ResultHandler<T> {

    private final Class<E> errorClass;
    private T result;
    private Throwable error;

    public ResultHolder(Class<E> errorClass) {
        this.errorClass = errorClass;
    }

    @Override
    public void handle(T t, Throwable e) {
        this.result = t;
        this.error = e;
    }

    public T getResult() throws E  {
        if (error != null) {
            if (errorClass.isInstance(error)) {
                throw errorClass.cast(error);
            } else if (error instanceof RuntimeException) {
                throw (RuntimeException) error;
            } else if (error instanceof Error) {
                throw (Error) error;
            } else {
                throw new RuntimeException(error);
            }
        }
        return result;
    }
}