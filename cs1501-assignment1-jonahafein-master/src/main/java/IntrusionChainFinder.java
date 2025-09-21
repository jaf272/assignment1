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
  public static List<List<Hop>> findChains(
      ScenarioFactory.Scenario scenario,
      SystemInfo start,
      SystemInfo target,
      int maxHops) {

    // TODO: implement recursive backtracking search using a helper recursive method

    


    return new ArrayList<>();
  }

    // need to implement all helper methods

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

    // if info missing we can't find a route
    if(from == null || to == null || svc == null){
      System.out.println("Missing a value cannot find a route");
      return null;
    }

    // if no routes defined from from, return null
    if(from.routes == null || from.routes.size() == 0){
      System.out.println("No outgoing routes from" + from.name);
      return null;
    }


    // now looking at each outgoing route from the from 
    for(int i = 0; i<from.routes.size(); i++){
      Route r = from.routes.get(i);


    }


  }


}
