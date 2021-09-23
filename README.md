## Lockless slab cache: Towards more fast slab allocator

On some workloads, it turns out that slab allocator's allocation speed became bottleneck.  
and some subsystems are making custom allocator based on slab allocator.  
but it is better to generalize them.  
  
This project tries to add lockless cache fastpath on existing slab allocator.  
Feel free to create an issue or discussion, or send merge request.  

This repository will be randomly updated (hopefully every 1~3 days, or every week)  

My email is:  
	- Hyeonggon Yoo <42.hyeyoo@gmail.com>  

Link: [More IOPS with Bio caching on LWN.net](https://lwn.net/Articles/868070/)  
Link: [Enable bio recycling for polled IO](https://www.spinics.net/lists/linux-block/msg71964.html)  

RFC v1 : https://lkml.org/lkml/2021/9/20/606  
RFC v2 : https://lkml.org/lkml/2021/9/20/600  
