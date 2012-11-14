package com.ctlok.web.session;

/**
 * @author Lawrence Cheung
 *
 */
public class StatelessSessionHolder {

    private static final ThreadLocal<StatelessSession> holder = new ThreadLocal<StatelessSession>();
    
    static void put(final StatelessSession statelessSession){
        holder.set(statelessSession);
    }
    
    static void remove(){
        holder.remove();
    }
    
    public static StatelessSession get(){
        return holder.get();
    }
    
}
