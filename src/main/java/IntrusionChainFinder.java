import java.util.*;

public final class IntrusionChainFinder {

  /**
   * Perform a recursive backtracking search to find all valid chains from start to target.
   * A chain stops immediately upon first reaching target.
   *
   * @param scenario the scenario containing all systems and exploits
   * @param start    the system where the attacker begins
   * @param target   the system the attacker is trying to reach
   * @param maxHops  maximum number of hops allowed in a chain
   * @return a list of valid chains (each chain is a list of Hop objects)
   */

   // building a sort key for a chain
   private static String keyForChain(List<Hop> chain){
    if(chain == null){
      return "";
    }

    StringBuilder sb = new StringBuilder();
    for(Hop h: chain){
      if(h == null){
        continue;
      }

      // append fields
      sb.append(h.from);
      sb.append("|");
      sb.append(h.viaService);
      sb.append("|");
      sb.append(h.viaExploit);
      sb.append("|");
      sb.append(h.to);
      sb.append("->");
    }

    return sb.toString();
   }

  public static List<List<Hop>> findChains(
      ScenarioFactory.Scenario scenario,
      SystemInfo start,
      SystemInfo target,
      int maxHops) {

    // TODO: implement recursive backtracking search using a helper recursive method

    // prep mutable searchn state
    Map<SystemInfo, Priv> privMap = new HashMap<>();
    for(SystemInfo s: scenario.systems){
      privMap.put(s, s.priv);
    }
    
    // inventory
    Set<String> inventory = new HashSet<>();
    //

    // reuse tracking
    Map<String, Integer> limitedCount = new HashMap<>();
    Map<String, Set<SystemInfo>> usedOncePerSys = new HashMap<>();

    //avoid revisits
    Set<SystemInfo> visited = new HashSet<>();
    visited.add(start);

    // path & solutions containers
    List<Hop> path = new ArrayList<>();
    List<List<Hop>> solutions = new ArrayList<>();

    // exploit order
    List<Exploit> exploitsSorted = new ArrayList<>(scenario.exploits);
    exploitsSorted.sort(Comparator.comparing(e -> e.name));

    // do the search
    dfs(start, exploitsSorted, privMap, inventory, limitedCount, usedOncePerSys, visited, path, solutions, target, maxHops);
    // sort solutions
    solutions.sort(Comparator.comparing((List<Hop> c) -> keyForChain(c)).thenComparingInt(List::size));

    return solutions;
  }

    // need to implement all helper methods


  // this will be key for our recursion
  // undo changes recorded in a ChangeRecord 
  private static void undoChanges(ChangeRecord rec, Map<SystemInfo, Priv> privMap, Set<String> inventory,
  Map<String, Integer> limitedCount, Map<String, Set<SystemInfo>> usedOncePerSys){
    if(rec == null){
      return; // there are no changes to undo in this case
    }

    // remove the creds we added
    if(rec.addedCreds != null && !rec.addedCreds.isEmpty()){
      for(String c: rec.addedCreds){
        inventory.remove(c);
      }
    }

    // now we need to restore the previous priviledges
    if(rec.target != null){
      privMap.put(rec.target, rec.prevPriv);
      //System.out.println("We now have" + rec.prevPriv + "restored for" + rec.target.name);
    }

    // need to revert the count if we incremented it
    if(rec.limitedIncremented == true){
      if(rec.prevLimitedCount == 0){
        limitedCount.remove(rec.exploit.name);
      }
      else{
        limitedCount.put(rec.exploit.name, rec.prevLimitedCount);
      }
    }

    // need to revert the once per system 
    if(rec.onceAdded == true){
      Set<SystemInfo> set = usedOncePerSys.get(rec.exploit.name);
      if(set != null){
        set.remove(rec.target);
        if(set.isEmpty()){
          usedOncePerSys.remove(rec.exploit.name);
        }
      }
    }
  }

  // *** make sure to add check to stop early if we'd exceed the max hops ** 

  private static void tryLateralThenRecurse(Exploit ex, List<Exploit> exploitsSorted, SystemInfo src, SystemInfo dst, ScenarioFactory.Scenario scenario,
  List<Hop> path, List<List<Hop>> solutions, Map<SystemInfo, Priv> privMap, Set<String> inventory, 
  Map<String, Integer> limitedCount, Map<String, Set<SystemInfo>> usedOncePerSys, Set<SystemInfo> visited, 
  SystemInfo target, int maxHops){
    
    // can't have too many hops
    if(path.size() + 1 > maxHops){
      return;
    }

    // apply the exploit + record the hop on the path
    ChangeRecord rec = doLateralExploit(ex, src, dst, privMap, inventory, limitedCount, usedOncePerSys);
    Hop hop = makeHop(src, dst, ex);
    path.add(hop);

    // stop when target reached
    if(dst == target){
      List<Hop> solution = new ArrayList<>(path);
      // save solution
      solutions.add(solution);
      path.remove(path.size() - 1); // don't recvurse further (and below part of that idea too)
      undoChanges(rec, privMap, inventory, limitedCount, usedOncePerSys);
      return;
    }

    // o.w. recurse
    if(visited.contains(dst)){
      path.remove(path.size() - 1);
      undoChanges(rec, privMap, inventory, limitedCount, usedOncePerSys);
      return;

    }

    visited.add(dst);

    dfs(dst, exploitsSorted, privMap, inventory, limitedCount, usedOncePerSys, visited, path, solutions, 
    target, maxHops);
    visited.remove(dst);

    path.remove(path.size() - 1);
    undoChanges(rec, privMap, inventory, limitedCount, usedOncePerSys);


  }

  private static void dfs(SystemInfo current, List<Exploit> exploitsSorted, Map<SystemInfo, Priv> privMap,
  Set<String> inventory, Map<String, Integer> limitedCount, Map<String, Set<SystemInfo>> usedOncePerSys,
  Set<SystemInfo> visited, List<Hop> path, List<List<Hop>> solutions, SystemInfo target, int maxHops){
    // TODO implement


    // base case
    if(current == target){
      solutions.add(new ArrayList<>(path));
      return;
    }

    // recursive case
    // try each edxploit
    for(Exploit ex: exploitsSorted){
      boolean isLocal = (ex.requiredService == null || ex.requiredService.isEmpty());
      if(isLocal == true){
        if(path.size() + 1 > maxHops){
          // can't keep adding here
          continue;
        }
        boolean conds_hold = preconditions_hold(ex, current, current, inventory, privMap, limitedCount, usedOncePerSys);
        if(!conds_hold){
          continue; // we continue on if our preconditions do not hold
        }
        // apply local ex
        ChangeRecord rec = doLocalExploit(ex, current, privMap, inventory, limitedCount, usedOncePerSys);
        // hop
        Hop hop = makeHop(current, current, ex);
        path.add(hop);

        if(current == target){
          solutions.add(new ArrayList<>(path));
          path.remove(path.size() -1);
          undoChanges(rec, privMap, inventory, limitedCount, usedOncePerSys);
          return;
        }

        // recurse
        dfs(current, exploitsSorted, privMap, inventory, limitedCount, usedOncePerSys, visited, path,
        solutions, target, maxHops);

        // remove hop and undo changes
        path.remove(path.size() - 1);
        undoChanges(rec, privMap, inventory, limitedCount, usedOncePerSys);
        // next ex
        continue;
      }

      if(current.routes != null){
        for(Route r: current.routes){
          if(r == null || r.to == null){
            continue;
          }
          SystemInfo dst = r.to;

          if(path.size()+ 1 > maxHops){
            continue;
          }

          // dont revisitr
          if(visited.contains(dst)){
            continue;
          }

          // preconditions for lateral
          boolean preconds_hold = preconditions_hold(ex, current, dst, inventory, privMap, limitedCount, usedOncePerSys);
          if(!preconds_hold){
            continue;
          }

          // apply lateral exploit
          ChangeRecord rec = doLateralExploit(ex, current, dst, privMap, inventory, limitedCount, usedOncePerSys);
          //add Hop
          Hop hop = makeHop(current, dst, ex);
          path.add(hop);


          // reached target check
          if(dst == target){
            solutions.add(new ArrayList<>(path));
            path.remove(path.size() - 1);
            undoChanges(rec, privMap, inventory, limitedCount, usedOncePerSys);
            // dont recurse past target
            continue;
          }

          // o.w. recurse from dst
          visited.add(dst);
          dfs(dst, exploitsSorted, privMap, inventory, limitedCount, usedOncePerSys, visited,
          path, solutions, target, maxHops);
          visited.remove(dst);


          // backtrack
          path.remove(path.size() -1);
          undoChanges(rec, privMap, inventory, limitedCount, usedOncePerSys);

        }
      }

    }


  }

  // create hop object
  private static Hop makeHop(SystemInfo from, SystemInfo to, Exploit ex){
    
    // get from and to names as well as exploit name
    String fromName;
    String toName;
    String exName;
    if(from == null){
      fromName = "null";
    }
    else{
      fromName = from.name;
    }

    if(to == null){
      toName = "null";
    }
    else{
      toName = to.name;
    }

    if(ex == null){
      exName = "null";
    }
    else{
      exName = ex.name;
    }

    String service = "LOCAL"; // default
    if(ex != null && ex.requiredService != null && !ex.requiredService.isEmpty()){
      service = ex.requiredService;
    }

    return new Hop(fromName, toName, exName, service);




  }

  // method to return true if the exploit is a local exploit
  // private static boolean isLocal(Exploit ex){
  //   if(ex == null || ex.requiredService == null){
  //     return true;
  //   }
  //   return false;
  // }

  // helper method to get priviledge level in ordernal manner
  private static int priviledge_order(Priv p){
    if(p == Priv.ADMIN){
      return 2;
    }
    else if(p == Priv.USER){
      return 1;
    }
    else{
      return 0;
    }
  }

  private static boolean sufficient_priviledge(Priv have, Priv need){
    // no priviledge needed case
    if(need == null){
      return true;
    }
    // converting to numeric
    int have_numeric = priviledge_order(have);
    int need_numeric = priviledge_order(need);


    if(have_numeric >= need_numeric){
      return true;
    }
    else{
      return false;
    }
  }

  // method to see which priviledge is higher
  private static Priv priviledge_max(Priv a, Priv b){
    if(a == null){
      return b;
    }
    if(b == null){
      return a;
    }

    // get numeric values for priviledges
    int a_number = priviledge_order(a);
    int b_number = priviledge_order(b);

    if(a_number >= b_number){
      return a;
    }
    else{
      return b;
    }

  }

  // method to see if attacker has credential in inventory
  private static boolean has_cred_with_tag(Set<String> inventory, String tag){
    // case where no tag is required
    if(tag == null){
      return true;
    }
    if(tag.equals("")){
      return true;
    }
    // empty inventory case
    if(inventory == null){
      return false;
    }

    // seeing if any credential starts with tag
    for(String cred:inventory){
      if(cred.startsWith(tag)){
        return true;
      }
    }

    return false;

  }

  // find a route from and to that allows the svc service
  private static Route find_route_allowing(SystemInfo from, SystemInfo to, String svc){
    // simpler version than I had before
    if(from == null || to == null || svc == null){
      return null;
    }
    for(Route r: from.routes){
      if(r == null || r.to == null || r.allow == null){
        continue;
      }
      if(r.to.name.equals(to.name) && r.allow.contains(svc)){
        return r;
      }
    }
    return null;
  }

  // now method to check that the preconditions hold for an exploit
  // TODO: implement later
  private static boolean preconditions_hold(
    Exploit ex, SystemInfo from, SystemInfo to, Set<String> inventory, Map<SystemInfo, Priv> privMap,
    Map<String, Integer> globalUseCount, Map<String, Set<SystemInfo>> usedOncePerSystem){
      // placeholder
      // implementation
      if(ex == null){
        return false;
      }

      boolean isLocal;

      // figure out if local or lateral
      if(ex.requiredService == null || ex.requiredService.isEmpty()){
        isLocal = true;
      }
      else{
        isLocal = false;
      }

      // local has to be applied to the same system
      if(isLocal == true && !from.name.equals(to.name)){
        return false;
      }

      // lateral needs to have reequired service
      if(!isLocal && (ex.requiredService == null || ex.requiredService.isEmpty())){
        return false;
      }

      // priv on source
      Priv have = privMap.getOrDefault(from, Priv.NONE);
      if(!sufficient_priviledge(have, ex.requiredPrivOnSource)){
        return false;
      }

      // cred tag requirement
      if(!has_cred_with_tag(inventory, ex.requiredCredTag)){
        //System.out.println("missing required cred tag");
        return false;
      }

      // lateral specific checks
      if(!isLocal){
        Route r = find_route_allowing(from, to, ex.requiredService);
        if(r == null){
          return false;
        }
        if(to.services == null || !to.services.contains(ex.requiredService)){
          return false;
        }
      }

      // reuse policy
      if(ex.reusePolicy != null){
        if(ex.reusePolicy.kind == ReusePolicy.Kind.LIMITED){
          int used = globalUseCount.getOrDefault(ex.name, 0);
          if(used >= ex.reusePolicy.limit){
            return false;
          }
        }
        else if(ex.reusePolicy.kind == ReusePolicy.Kind.ONCE_PER_SYSTEM){
          Set<SystemInfo> usedOn = usedOncePerSystem.getOrDefault(ex.name, Collections.<SystemInfo>emptySet());
          SystemInfo scope;
          if(isLocal){
            scope = from;
          }
          else{
            scope = to;
          }
          if(usedOn.contains(scope)){
            return false;
          }
        }
      }

      return true;
      
      
  }

  // class and helper methods for remembering exploit application changes
  private static class ChangeRecord{
    Exploit exploit;
    SystemInfo target;
    Priv prevPriv;
    Set<String> addedCreds;
    int prevLimitedCount;
    boolean limitedIncremented;
    boolean onceAdded;

    ChangeRecord(Exploit exploit, SystemInfo target){
      this.exploit = exploit;
      this.target = target;
      this.addedCreds = new HashSet<>();
      this.prevLimitedCount = 0;
      this.limitedIncremented = false;
      this.onceAdded = false;
    }
  }

  // method to apply a local exploit's effects to the current system
  // TODO for later: implement
  private static ChangeRecord doLocalExploit(Exploit ex, SystemInfo current, Map<SystemInfo, Priv> privMap,
  Set<String> inventory, Map<String, Integer> limitedCount, Map<String, Set<SystemInfo>> usedOncePerSys){
    
    // Record we will return
    ChangeRecord rec = new ChangeRecord(ex, current);

    // account for reusing
    if(ex.reusePolicy != null){
      if(ex.reusePolicy.kind == ReusePolicy.Kind.LIMITED){
        int prev = limitedCount.getOrDefault(ex.name, 0);
        rec.prevLimitedCount = prev;
        limitedCount.put(ex.name, prev + 1);
        rec.limitedIncremented = true;
      }
      else if(ex.reusePolicy.kind == ReusePolicy.Kind.ONCE_PER_SYSTEM){
        Set<SystemInfo> set = usedOncePerSys.get(ex.name);
        if(set == null){
          set = new HashSet<>();
          usedOncePerSys.put(ex.name, set);
        }
        boolean added = set.add(current);
        rec.onceAdded = added;
      }
      //else{
        //System.out.println("Unlimited reuse - nothing to worry about here.");
      //}
    }

    // priviledge gain stuff
    Priv oldPriv = privMap.getOrDefault(current, Priv.NONE);
    // we want to remember the previous
    rec.prevPriv = oldPriv;
    if (ex.gainPrivOnTarget != null){
      Priv newPriv = priviledge_max(oldPriv, ex.gainPrivOnTarget);
      privMap.put(current, newPriv);
    }

    // make logic to copy system creds into inventory
    if(ex.addCredsOnTarget == true){
      if(current.creds != null){
        for (String c: current.creds){
          if(!inventory.contains(c)){
            inventory.add(c);
            rec.addedCreds.add(c);
          }
        }
      }
    }

    return rec;


  }

  // method to apply a lateral exploits effects (src to dst)
  private static ChangeRecord doLateralExploit(Exploit ex, SystemInfo src, SystemInfo dst, Map<SystemInfo, Priv> privMap,
  Set<String> inventory, Map<String, Integer> limitedCount, Map<String, Set<SystemInfo>> usedOncePerSys){
    // creating the record to return
    ChangeRecord rec = new ChangeRecord(ex, dst);

    // account for the reuse
    if(ex.reusePolicy != null){
      if(ex.reusePolicy.kind == ReusePolicy.Kind.LIMITED){
        int prev = limitedCount.getOrDefault(ex.name, 0);
        rec.prevLimitedCount = prev;
        limitedCount.put(ex.name, prev + 1);
        rec.limitedIncremented = true;
      }
      else if(ex.reusePolicy.kind == ReusePolicy.Kind.ONCE_PER_SYSTEM){
        Set<SystemInfo> set = usedOncePerSys.get(ex.name);
        if(set == null){
          set = new HashSet<>();
          usedOncePerSys.put(ex.name, set);
        }
        boolean added = set.add(dst);
        rec.onceAdded = added;
      }
    }

    // priviledge gain after the move
    Priv oldPriv = privMap.getOrDefault(dst, Priv.NONE);
    rec.prevPriv = oldPriv;
    if(ex.gainPrivOnTarget != null){
      Priv newPriv = priviledge_max(oldPriv, ex.gainPrivOnTarget);
      privMap.put(dst, newPriv);
    }

    // 
    if(ex.addCredsOnTarget){
      if(dst.creds != null){
        for(String c: dst.creds){
          if(!inventory.contains(c)){
            inventory.add(c);
            rec.addedCreds.add(c);
          }
        }
      }
      
    }
    
    return rec;

  }



}
