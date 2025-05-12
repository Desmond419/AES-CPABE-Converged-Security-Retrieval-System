package com.lzk.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class AuditService {

    private final List<AuditLog> logs = Collections.synchronizedList(new ArrayList<>());

    public void record(String username, String action, String target, boolean success) {
        AuditLog log = new AuditLog(System.currentTimeMillis(), username, action, target, success);
        logs.add(log);
        System.out.println("AUDIT => " + log);
    }

    public List<AuditLog> getLogs() {
        return logs;
    }

    public static class AuditLog {
        public long timestamp;
        public String username;
        public String action;
        public String target;
        public boolean success;

        public AuditLog(long t, String u, String a, String tar, boolean s){
            timestamp = t; username=u; action=a; target=tar; success=s;
        }
        @Override
        public String toString(){
            return "[time="+timestamp+", user="+username+", action="+action+", target="+target+", success="+success+"]";
        }
    }
}
