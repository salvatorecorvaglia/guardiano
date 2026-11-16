import AsyncPicker from "../components/AsyncPicker";
import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { request } from "../api/typed";
import ScanTable from "../components/ScanTable";
import { ErrorBox, PageHeader, Pagination, Spinner } from "../components/ui";
import { optionalNumber, useClampPage, useUrlParams } from "../lib/urlState";

const PAGE_SIZE = 25;

export default function Scans() {
  const { params, update, page } = useUrlParams();

  const assetId = params.get("asset_id") ?? "";
  const scanType = params.get("scan_type") ?? "";
  const source = params.get("source") ?? "";

  const list = useQuery({
    queryKey: ["scans", "list", assetId, scanType, source, page],
    queryFn: ({ signal }) => request("get", "/api/v1/scans", { signal, query: { asset_id: optionalNumber(assetId), scan_type: scanType, source, page, page_size: PAGE_SIZE } }),
    placeholderData: keepPreviousData,
  });
  useClampPage(page, PAGE_SIZE, list.data?.total, update, list.isPlaceholderData);

  const set = (k: string, v: string) => update({ [k]: v || null });

  return (
    <>
      <PageHeader
        title="Scans"
        subtitle="Every imported SAST, SCA, IaC and DAST report, with its deduplication outcome. Previews (branch scans) change nothing."
      />
      <div className="mb-4 flex flex-wrap gap-2">
        <AsyncPicker kind="assets" label="Asset" value={assetId} emptyLabel="All assets" onChange={(value) => set("asset_id", value)} />
        <select className="input w-auto" value={scanType} onChange={(e) => set("scan_type", e.target.value)} aria-label="Scan type">
          <option value="">SAST + SCA</option>
          <option value="sast">SAST</option>
          <option value="sca">SCA</option>
          <option value="iac">IaC</option>
          <option value="dast">DAST</option>
        </select>
        <select className="input w-auto" value={source} onChange={(e) => set("source", e.target.value)} aria-label="Source">
          <option value="">All sources</option>
          <option value="upload">UI uploads</option>
          <option value="api">API (CI)</option>
          <option value="preview">Previews only</option>
        </select>
      </div>
      <ErrorBox error={list.error} />
      <div className="card overflow-hidden">
        {list.isLoading ? (
          <div className="flex justify-center py-12">
            <Spinner />
          </div>
        ) : (
          <ScanTable scans={list.data?.items ?? []} showAsset />
        )}
        {list.data && list.data.total > 0 && (
          <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={(p) => update({ page: String(p) }, true)} />
        )}
      </div>
    </>
  );
}
