@load base/frameworks/sumstats

global all_count = 0;

event zeek_init()
{
	local r1 = SumStats::Reducer($stream="404detect", $apply=set(SumStats::UNIQUE,SumStats::SUM));
	SumStats::create([$name="404count",
					  $epoch=10min,
					  $reducers=set(r1),
					  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
					  {
					  		local r = result["404detect"];
					  		if(r$num>2)
					  		{
					  			if(r$num/all_count>0.2)
					  			{
					  				if((r$unique/r$num)>0.5)
					  				{
					  					print fmt("%s is a scanner with %d scan attempts on %d urls",key$host,r$num,r$unique);
					  				}
					  			}
					  		}
					  }
	                 ]
	);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	all_count = all_count + 1;
	if(code==404)
	{
		SumStats::observe("404detect", [$host=c$id$orig_h], [$str=reason]);
	}
}