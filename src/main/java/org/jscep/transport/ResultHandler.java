package org.jscep.transport;


public interface ResultHandler<T> {
    void handle(T t, Throwable e);
}